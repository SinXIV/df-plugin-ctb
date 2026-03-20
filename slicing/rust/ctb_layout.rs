use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;
use sha2::{Digest, Sha256};

use super::ctb_crypto::{
    ctb_encrypt_in_place_no_padding, ctb_encrypt_padded_vec, pad_vec_to_block,
    resolve_ctb_aes_material,
};
use super::ctb_metadata::{
    decode_embedded_disclaimer_bytes, parse_ctb_aes_model_from_job, parse_ctb_build_model_from_job,
    parse_ctb_resin_model_from_job, parse_machine_software_version,
    parse_timing_model_from_metadata,
};
use super::ctb_preview::{build_previews, write_preview_record};
use super::ctb_types::{
    CtbBuildModel, CtbExtendedOffsets, CtbPreparedLayer, CtbPreviewOffsets, CtbResinModel,
    CtbResinPayload, CtbTimingModel, CTB_DISCLAIMER_SIZE, CTB_HEADER_SIZE, CTB_LAYER_DEF_EX_SIZE,
    CTB_LAYER_DEF_SIZE, CTB_MAGIC_V2_V3, CTB_MAGIC_V4_V5, CTB_MAGIC_V5_ENCRYPTED, CTB_PAGE_SIZE,
    CTB_PREVIEW_RECORD_SIZE, CTB_PRINT_PARAMETERS_SIZE, CTB_PRINT_PARAMETERS_V4_RESERVED_SIZE,
    CTB_PRINT_PARAMETERS_V4_SIZE, CTB_SLICER_INFO_FIXED_SIZE,
};

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_f32(out: &mut Vec<u8>, value: f32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes_padded(out: &mut Vec<u8>, bytes: &[u8], target_len: usize) {
    if bytes.len() >= target_len {
        out.extend_from_slice(&bytes[..target_len]);
        return;
    }

    out.extend_from_slice(bytes);
    out.resize(out.len() + (target_len - bytes.len()), 0);
}

fn ctb_magic_for_version(version: u32, aes_enabled: bool) -> u32 {
    if aes_enabled && version >= 5 {
        CTB_MAGIC_V5_ENCRYPTED
    } else if version >= 4 {
        CTB_MAGIC_V4_V5
    } else {
        CTB_MAGIC_V2_V3
    }
}

fn page_number_and_offset(absolute_offset: u64) -> (u32, u32) {
    let page = (absolute_offset / CTB_PAGE_SIZE) as u32;
    let offset = (absolute_offset - (page as u64) * CTB_PAGE_SIZE) as u32;
    (page, offset)
}

#[cfg(test)]
pub(super) fn rle_encode_mask_row_major(mask: &[u8]) -> Vec<u8> {
    if mask.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(mask.len() / 2);
    let mut run_value = mask[0];
    let mut run_len: u32 = 1;

    for &px in &mask[1..] {
        if px == run_value {
            run_len = run_len.saturating_add(1);
            continue;
        }

        push_ctb_run(&mut out, run_len, run_value);
        run_value = px;
        run_len = 1;
    }

    push_ctb_run(&mut out, run_len, run_value);
    out
}

fn rle_encode_thresholded_row_major(mask: &[u8], threshold: u8) -> Vec<u8> {
    if mask.is_empty() {
        return Vec::new();
    }

    // CTB output is highly compressed; start small to avoid massive heap allocations
    // that serialize on the OS allocator lock, causing low CPU utilization.
    let mut out = Vec::with_capacity(32 * 1024);
    let mut run_value = if mask[0] > threshold { 255 } else { 0 };
    let mut run_len = 0u32;
    let mut i = 0;

    let len = mask.len();
    while i < len {
        let chunk = &mask[i..];
        if run_value == 0 {
            if let Some(pos) = chunk.iter().position(|&x| x > threshold) {
                run_len += pos as u32;
                i += pos;
                push_ctb_run(&mut out, run_len, run_value);
                run_value = 255;
                run_len = 0;
            } else {
                run_len += (len - i) as u32;
                break;
            }
        } else {
            if let Some(pos) = chunk.iter().position(|&x| x <= threshold) {
                run_len += pos as u32;
                i += pos;
                push_ctb_run(&mut out, run_len, run_value);
                run_value = 0;
                run_len = 0;
            } else {
                run_len += (len - i) as u32;
                break;
            }
        }
    }

    if run_len > 0 {
        push_ctb_run(&mut out, run_len, run_value);
    }
    out
}

pub(super) fn encode_single_ctb_layer_from_raw_mask(
    layer_index: usize,
    raw_mask: &[u8],
    threshold: u8,
    layer_xor_key: u32,
) -> CtbPreparedLayer {
    let mut encoded = rle_encode_thresholded_row_major(raw_mask, threshold);
    ctb_layer_rle_xor(layer_xor_key, layer_index as u32, &mut encoded);
    CtbPreparedLayer {
        index: layer_index,
        source_len: raw_mask.len(),
        encoded,
    }
}

pub(super) fn encode_single_ctb_empty_layer(
    layer_index: usize,
    expected_pixels: usize,
    layer_xor_key: u32,
) -> CtbPreparedLayer {
    let mut encoded = Vec::with_capacity(5);
    push_ctb_run(
        &mut encoded,
        expected_pixels.min(u32::MAX as usize) as u32,
        0,
    );
    ctb_layer_rle_xor(layer_xor_key, layer_index as u32, &mut encoded);
    CtbPreparedLayer {
        index: layer_index,
        source_len: expected_pixels,
        encoded,
    }
}

pub(super) fn push_ctb_run(out: &mut Vec<u8>, len: u32, value_8bit: u8) {
    if len == 0 {
        return;
    }

    let mut code = value_8bit >> 1;
    if len > 1 {
        code |= 0x80;
    }
    out.push(code);

    if len <= 1 {
        return;
    }

    if len <= 0x7f {
        out.push(len as u8);
        return;
    }

    if len <= 0x3fff {
        out.push(((len >> 8) as u8) | 0x80);
        out.push(len as u8);
        return;
    }

    if len <= 0x1f_ffff {
        out.push(((len >> 16) as u8) | 0xc0);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        return;
    }

    let clamped = len.min(0x0fff_ffff);
    out.push(((clamped >> 24) as u8) | 0xe0);
    out.push((clamped >> 16) as u8);
    out.push((clamped >> 8) as u8);
    out.push(clamped as u8);
}

#[cfg(test)]
pub(super) fn normalize_to_binary_mask(mask: &[u8], threshold: u8) -> (Vec<u8>, u32) {
    let mut out = Vec::with_capacity(mask.len());
    let mut lit_pixels: u32 = 0;

    for &px in mask {
        let bin = if px > threshold { 255 } else { 0 };
        if bin == 255 {
            lit_pixels = lit_pixels.saturating_add(1);
        }
        out.push(bin);
    }

    (out, lit_pixels)
}

pub(super) fn ctb_layer_rle_xor(seed: u32, layer_index: u32, bytes: &mut [u8]) {
    if seed == 0 {
        return;
    }

    let init = seed.wrapping_mul(0x2d83_cdac).wrapping_add(0xd8a8_3423);
    let mut key = layer_index
        .wrapping_mul(0x1e15_30cd)
        .wrapping_add(0xec3d_47cd)
        .wrapping_mul(init);

    // Fast path: bulk process 4 bytes at a time
    let mut chunks = bytes.chunks_exact_mut(4);
    for chunk in &mut chunks {
        // key is applied byte-by-byte in little-endian order: (key>>0), (key>>8), (key>>16), (key>>24)
        let key_bytes = key.to_le_bytes();
        chunk[0] ^= key_bytes[0];
        chunk[1] ^= key_bytes[1];
        chunk[2] ^= key_bytes[2];
        chunk[3] ^= key_bytes[3];
        key = key.wrapping_add(init);
    }

    // Handle remaining 1-3 bytes
    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        let key_bytes = key.to_le_bytes();
        for (i, b) in remainder.iter_mut().enumerate() {
            *b ^= key_bytes[i];
        }
    }
}

pub(super) fn prepare_layers_for_ctb(
    raw_masks: &[Vec<u8>],
    threshold: u8,
    layer_xor_key: u32,
) -> Vec<CtbPreparedLayer> {
    prepare_layers_for_ctb_with_progress(raw_masks, threshold, layer_xor_key, None)
}

pub(super) fn prepare_layers_for_ctb_with_progress(
    raw_masks: &[Vec<u8>],
    threshold: u8,
    layer_xor_key: u32,
    on_progress: Option<&dyn Fn(u32, u32)>,
) -> Vec<CtbPreparedLayer> {
    let total = raw_masks.len() as u32;
    let mut out = Vec::with_capacity(raw_masks.len());

    for (index, layer) in raw_masks.iter().enumerate() {
        out.push(encode_single_ctb_layer_from_raw_mask(
            index,
            layer,
            threshold,
            layer_xor_key,
        ));

        if let Some(progress) = on_progress {
            progress((index as u32) + 1, total.max(1));
        }
    }

    out
}

fn write_ctb_header(
    out: &mut Vec<u8>,
    magic: u32,
    version: u32,
    job: &SliceJobV3,
    layer_count: u32,
    timing: CtbTimingModel,
    build: &CtbBuildModel,
    preview_offsets: CtbPreviewOffsets,
    print_parameters_offset: u32,
    layers_definition_offset: u32,
    print_time_sec: u32,
    slicer_offset: u32,
    slicer_size: u32,
) {
    push_u32(out, magic);
    push_u32(out, version);
    push_f32(out, job.build_width_mm);
    push_f32(out, job.build_depth_mm);
    push_f32(out, build.bed_size_z_mm.max(0.0));
    push_u32(out, build.created_date_unix);
    push_u32(out, build.modified_date_unix);
    push_f32(out, job.layer_height_mm * layer_count as f32);
    push_f32(out, job.layer_height_mm);
    push_f32(out, timing.normal_exposure_sec);
    push_f32(out, timing.bottom_exposure_sec);
    push_f32(out, timing.light_off_delay_sec);
    push_u32(out, timing.bottom_layer_count);
    push_u32(out, job.source_width_px);
    push_u32(out, job.source_height_px);
    push_u32(out, preview_offsets.large_record_offset);
    push_u32(out, layers_definition_offset);
    push_u32(out, layer_count);
    push_u32(out, preview_offsets.small_record_offset);
    push_u32(out, print_time_sec);
    push_u32(out, build.projector_type);
    push_u32(out, print_parameters_offset);
    push_u32(out, CTB_PRINT_PARAMETERS_SIZE);
    push_u32(out, 1);
    push_u16(out, 255);
    push_u16(out, 255);
    push_u32(out, build.layer_xor_key);
    push_u32(out, slicer_offset);
    push_u32(out, slicer_size);
}

fn write_ctb_print_parameters(out: &mut Vec<u8>, timing: CtbTimingModel) {
    push_f32(out, timing.lift_distance_mm);
    push_f32(out, timing.lift_speed_mm_min);
    push_f32(out, timing.lift_distance_mm);
    push_f32(out, timing.lift_speed_mm_min);
    push_f32(out, timing.retract_speed_mm_min);
    push_f32(out, 0.0);
    push_f32(out, 0.0);
    push_f32(out, 0.0);
    push_f32(out, timing.bottom_light_off_delay_sec);
    push_f32(out, timing.light_off_delay_sec);
    push_u32(out, timing.bottom_layer_count);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 0);
}

fn write_ctb_slicer_info_fixed(
    out: &mut Vec<u8>,
    build: &CtbBuildModel,
    timing: CtbTimingModel,
    machine_name_offset: u32,
    machine_name_size: u32,
    print_parameters_v4_address: u32,
) {
    push_f32(out, timing.lift_distance_mm);
    push_f32(out, timing.lift_speed_mm_min);
    push_f32(out, 0.0);
    push_f32(out, 0.0);
    push_f32(out, timing.bottom_retract_height2_mm);
    push_f32(out, timing.bottom_retract_speed2_mm_min);
    push_f32(out, timing.wait_time_after_lift_sec);

    push_u32(out, machine_name_offset);
    push_u32(out, machine_name_size);

    push_u8(
        out,
        if build.anti_alias_level > 1 {
            0x0f
        } else {
            0x07
        },
    );
    push_u16(out, 0);
    push_u8(
        out,
        if build.per_layer_settings {
            if build.version >= 5 {
                0x50
            } else {
                0x40
            }
        } else {
            0x00
        },
    );

    push_u32(out, 0);
    push_u32(out, build.anti_alias_level);
    push_u32(out, parse_machine_software_version(build.version));

    push_f32(out, timing.wait_time_before_cure_sec);
    push_f32(out, timing.wait_time_after_lift_sec);
    push_u32(out, timing.transition_layer_count);
    push_u32(out, print_parameters_v4_address);
    push_u32(out, 0);
    push_u32(out, 0);
}

fn write_ctb_print_parameters_v4(
    out: &mut Vec<u8>,
    timing: CtbTimingModel,
    layer_count: u32,
    extended_offsets: CtbExtendedOffsets,
) {
    push_f32(out, timing.bottom_retract_speed_mm_min);
    push_f32(out, timing.bottom_retract_speed2_mm_min);
    push_u32(out, 0);
    push_f32(out, 4.0);
    push_u32(out, 0);
    push_f32(out, 4.0);
    push_f32(out, timing.wait_time_before_cure_sec);
    push_f32(out, timing.wait_time_after_lift_sec);
    push_f32(out, timing.wait_time_after_cure_sec);
    push_f32(out, timing.bottom_retract_height2_mm);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 5);
    push_u32(out, layer_count.saturating_sub(1));
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, extended_offsets.disclaimer_offset);
    push_u32(out, extended_offsets.disclaimer_length);
    push_u32(out, extended_offsets.resin_parameters_offset);
    out.extend_from_slice(&[0u8; CTB_PRINT_PARAMETERS_V4_RESERVED_SIZE]);
}

fn prepare_resin_payload(
    build: &CtbBuildModel,
    resin: &CtbResinModel,
    aes_enabled: bool,
) -> CtbResinPayload {
    let mut machine_name_bytes = build.machine_name.as_bytes().to_vec();
    let mut resin_type_bytes = resin.resin_type.as_bytes().to_vec();
    let mut resin_name_bytes = resin.resin_name.as_bytes().to_vec();

    if build.version >= 5 {
        if !machine_name_bytes.ends_with(&[0]) {
            machine_name_bytes.push(0);
        }
        if !resin_type_bytes.ends_with(&[0]) {
            resin_type_bytes.push(0);
        }
        if !resin_name_bytes.ends_with(&[0]) {
            resin_name_bytes.push(0);
        }
    }

    let base_len =
        40usize + resin_type_bytes.len() + resin_name_bytes.len() + machine_name_bytes.len();
    let tail_padding_bytes = if aes_enabled {
        (16 - (base_len % 16)) % 16
    } else {
        0
    };

    CtbResinPayload {
        machine_name_bytes,
        resin_type_bytes,
        resin_name_bytes,
        tail_padding_bytes,
    }
}

fn resin_payload_len(payload: &CtbResinPayload) -> u32 {
    40 + payload.resin_type_bytes.len() as u32
        + payload.resin_name_bytes.len() as u32
        + payload.machine_name_bytes.len() as u32
        + payload.tail_padding_bytes as u32
}

fn write_ctb_resin_parameters(
    out: &mut Vec<u8>,
    resin_offset: u32,
    payload: &CtbResinPayload,
    resin: &CtbResinModel,
) {
    let fixed_size = 40u32;
    let resin_type_address = resin_offset + fixed_size;
    let resin_name_address = resin_type_address + payload.resin_type_bytes.len() as u32;
    let machine_name_address = resin_name_address + payload.resin_name_bytes.len() as u32;

    push_u32(out, 0);
    push_u8(out, resin.color_rgba[2]);
    push_u8(out, resin.color_rgba[1]);
    push_u8(out, resin.color_rgba[0]);
    push_u8(out, resin.color_rgba[3]);

    push_u32(out, machine_name_address);
    push_u32(out, payload.resin_type_bytes.len() as u32);
    push_u32(out, resin_type_address);
    push_u32(out, payload.resin_name_bytes.len() as u32);
    push_u32(out, resin_name_address);
    push_u32(out, payload.machine_name_bytes.len() as u32);
    push_f32(out, resin.resin_density);
    push_u32(out, 0);

    out.extend_from_slice(&payload.resin_type_bytes);
    out.extend_from_slice(&payload.resin_name_bytes);
    out.extend_from_slice(&payload.machine_name_bytes);
    if payload.tail_padding_bytes != 0 {
        out.resize(out.len() + payload.tail_padding_bytes, 0);
    }
}

fn write_layer_def(
    out: &mut Vec<u8>,
    layer: &CtbPreparedLayer,
    position_z_mm: f32,
    exposure_sec: f32,
    light_off_sec: f32,
    data_abs_offset: u64,
) {
    let (page_number, data_offset) = page_number_and_offset(data_abs_offset);

    push_f32(out, position_z_mm);
    push_f32(out, exposure_sec);
    push_f32(out, light_off_sec);
    push_u32(out, data_offset);
    push_u32(out, layer.encoded.len() as u32);
    push_u32(out, page_number);
    push_u32(out, CTB_LAYER_DEF_SIZE);
    push_u32(out, 0);
    push_u32(out, 0);
}

fn write_layer_def_ex(
    out: &mut Vec<u8>,
    layer: &CtbPreparedLayer,
    layer_def_bytes: &[u8],
    timing: CtbTimingModel,
) {
    out.extend_from_slice(layer_def_bytes);
    push_u32(out, CTB_LAYER_DEF_EX_SIZE + layer.encoded.len() as u32);

    push_f32(out, timing.lift_distance_mm);
    push_f32(out, timing.lift_speed_mm_min);
    push_f32(out, 0.0);
    push_f32(out, 0.0);
    push_f32(out, timing.retract_speed_mm_min);
    push_f32(out, 0.0);
    push_f32(out, 0.0);
    push_f32(out, timing.wait_time_after_cure_sec);
    push_f32(out, timing.wait_time_after_lift_sec);
    push_f32(out, timing.wait_time_before_cure_sec);
    push_f32(out, 255.0);
}

fn compute_print_time_seconds(prepared_count: usize, timing: CtbTimingModel) -> u32 {
    let mut total = 0.0_f32;
    for i in 0..prepared_count {
        let is_bottom = (i as u32) < timing.bottom_layer_count;
        let exposure = if is_bottom {
            timing.bottom_exposure_sec
        } else {
            timing.normal_exposure_sec
        };
        let light_off = if is_bottom {
            timing.bottom_light_off_delay_sec
        } else {
            timing.light_off_delay_sec
        };

        total += exposure.max(0.0)
            + light_off.max(0.0)
            + timing.lift_distance_mm.max(0.0)
            + timing.retract_speed_mm_min.max(0.0) * 0.0;
    }
    total.round().max(0.0) as u32
}

pub(super) fn build_ctb_container_bytes(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
) -> Result<Vec<u8>, SlicerV3Error> {
    build_ctb_container_bytes_with_progress(job, prepared, None)
}

pub(super) fn build_ctb_container_bytes_with_progress(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    on_progress: Option<&dyn Fn(u32, u32)>,
) -> Result<Vec<u8>, SlicerV3Error> {
    let timing = parse_timing_model_from_metadata(&job.metadata_json);
    let build = parse_ctb_build_model_from_job(job);
    let resin = parse_ctb_resin_model_from_job(job, &build.machine_name);
    let aes = parse_ctb_aes_model_from_job(job);
    let aes_material = resolve_ctb_aes_material(&aes)?;
    let aes_enabled = aes_material.is_some();

    if aes_enabled && build.version != 5 {
        return Err(SlicerV3Error::UnsupportedOutput(
            "CTB AES mode currently requires CTB version 5".to_string(),
        ));
    }

    let previews = build_previews(job)?;

    let mut machine_name_bytes = build.machine_name.as_bytes().to_vec();
    if build.version >= 5 && !machine_name_bytes.ends_with(&[0]) {
        machine_name_bytes.push(0);
    }
    if aes_enabled {
        pad_vec_to_block(&mut machine_name_bytes, 16);
    }
    let machine_name_size = machine_name_bytes.len() as u32;

    let layer_count = prepared.len() as u32;

    let mut offset = CTB_HEADER_SIZE;

    let large_preview_record_offset = offset;
    let large_preview_image_offset = large_preview_record_offset + CTB_PREVIEW_RECORD_SIZE;
    offset = large_preview_image_offset + previews[0].encoded.len() as u32;

    let small_preview_record_offset = offset;
    let small_preview_image_offset = small_preview_record_offset + CTB_PREVIEW_RECORD_SIZE;
    offset = small_preview_image_offset + previews[1].encoded.len() as u32;

    let print_parameters_offset = offset;
    offset += CTB_PRINT_PARAMETERS_SIZE;

    let slicer_offset = offset;
    let slicer_size = CTB_SLICER_INFO_FIXED_SIZE;
    offset += slicer_size;

    let machine_name_offset = offset;
    offset += machine_name_size;

    let disclaimer_bytes = decode_embedded_disclaimer_bytes()?;

    let resin_payload = prepare_resin_payload(&build, &resin, aes_enabled && build.version >= 5);

    let mut extended_offsets = CtbExtendedOffsets {
        disclaimer_offset: 0,
        disclaimer_length: 0,
        print_parameters_v4_offset: 0,
        resin_parameters_offset: 0,
    };

    if build.version >= 4 {
        extended_offsets.disclaimer_offset = offset;
        extended_offsets.disclaimer_length = CTB_DISCLAIMER_SIZE as u32;
        offset += CTB_DISCLAIMER_SIZE as u32;

        extended_offsets.print_parameters_v4_offset = offset;
        offset += CTB_PRINT_PARAMETERS_V4_SIZE;

        if build.version >= 5 {
            extended_offsets.resin_parameters_offset = offset;
            offset += resin_payload_len(&resin_payload);
        }
    }

    let layers_definition_offset = offset;

    let mut layer_defs_data = Vec::with_capacity(prepared.len() * CTB_LAYER_DEF_SIZE as usize);
    let mut layer_ex_and_payload = Vec::new();

    let layer_defs_total_size = layer_count as u64 * CTB_LAYER_DEF_SIZE as u64;
    let mut rolling_data_abs = layers_definition_offset as u64 + layer_defs_total_size;

    let layer_total = prepared.len() as u32;
    for (layer_step, layer) in prepared.iter().enumerate() {
        let position_z = (layer.index as f32 + 1.0) * job.layer_height_mm;
        let is_bottom = (layer.index as u32) < timing.bottom_layer_count;
        let exposure = if is_bottom {
            timing.bottom_exposure_sec
        } else {
            timing.normal_exposure_sec
        };
        let light_off = if is_bottom {
            timing.bottom_light_off_delay_sec
        } else {
            timing.light_off_delay_sec
        };

        let data_abs = if build.version >= 3 {
            rolling_data_abs + CTB_LAYER_DEF_EX_SIZE as u64
        } else {
            rolling_data_abs
        };

        let mut one_def = Vec::with_capacity(CTB_LAYER_DEF_SIZE as usize);
        write_layer_def(
            &mut one_def,
            layer,
            position_z,
            exposure,
            light_off,
            data_abs,
        );
        layer_defs_data.extend_from_slice(&one_def);

        if build.version >= 3 {
            let mut ex = Vec::with_capacity(CTB_LAYER_DEF_EX_SIZE as usize);
            write_layer_def_ex(&mut ex, layer, &one_def, timing);
            layer_ex_and_payload.extend_from_slice(&ex);
            rolling_data_abs = rolling_data_abs.saturating_add(CTB_LAYER_DEF_EX_SIZE as u64);
        }

        layer_ex_and_payload.extend_from_slice(&layer.encoded);
        rolling_data_abs = rolling_data_abs.saturating_add(layer.encoded.len() as u64);

        if let Some(progress) = on_progress {
            progress((layer_step as u32) + 1, layer_total.max(1));
        }
    }

    let mut out = Vec::with_capacity(rolling_data_abs as usize + 2048);

    let print_time_sec = compute_print_time_seconds(prepared.len(), timing);

    write_ctb_header(
        &mut out,
        ctb_magic_for_version(build.version, aes_enabled),
        build.version,
        job,
        layer_count,
        timing,
        &build,
        CtbPreviewOffsets {
            large_record_offset: large_preview_record_offset,
            small_record_offset: small_preview_record_offset,
        },
        print_parameters_offset,
        layers_definition_offset,
        print_time_sec,
        slicer_offset,
        slicer_size,
    );

    if out.len() as u32 != CTB_HEADER_SIZE {
        return Err(SlicerV3Error::UnsupportedOutput(format!(
            "internal CTB header size mismatch: expected {}, got {}",
            CTB_HEADER_SIZE,
            out.len()
        )));
    }

    write_preview_record(
        &mut out,
        previews[0].width,
        previews[0].height,
        large_preview_image_offset,
        previews[0].encoded.len() as u32,
    );
    out.extend_from_slice(&previews[0].encoded);

    write_preview_record(
        &mut out,
        previews[1].width,
        previews[1].height,
        small_preview_image_offset,
        previews[1].encoded.len() as u32,
    );
    out.extend_from_slice(&previews[1].encoded);

    write_ctb_print_parameters(&mut out, timing);

    write_ctb_slicer_info_fixed(
        &mut out,
        &build,
        timing,
        machine_name_offset,
        machine_name_size,
        extended_offsets.print_parameters_v4_offset,
    );
    out.extend_from_slice(&machine_name_bytes);

    if build.version >= 4 {
        push_bytes_padded(&mut out, &disclaimer_bytes, CTB_DISCLAIMER_SIZE);
        write_ctb_print_parameters_v4(&mut out, timing, layer_count, extended_offsets);

        if build.version >= 5 {
            write_ctb_resin_parameters(
                &mut out,
                extended_offsets.resin_parameters_offset,
                &resin_payload,
                &resin,
            );
        }
    }

    out.extend_from_slice(&layer_defs_data);
    out.extend_from_slice(&layer_ex_and_payload);

    if let Some((key, iv)) = aes_material {
        let settings_start = print_parameters_offset as usize;
        let settings_end = layers_definition_offset as usize;
        if settings_end > out.len() || settings_start >= settings_end {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES settings block out of range ({settings_start}..{settings_end}, len {})",
                out.len()
            )));
        }

        let machine_name_start = machine_name_offset as usize;
        let machine_name_end = machine_name_start.saturating_add(machine_name_size as usize);
        if machine_name_end > out.len() {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES machine-name block out of range ({machine_name_start}..{machine_name_end}, len {})",
                out.len()
            )));
        }
        ctb_encrypt_in_place_no_padding(&mut out[machine_name_start..machine_name_end], &key, &iv)?;

        let disclaimer_start = extended_offsets.disclaimer_offset as usize;
        let disclaimer_end = disclaimer_start.saturating_add(CTB_DISCLAIMER_SIZE);
        if disclaimer_end > out.len() {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES disclaimer block out of range ({disclaimer_start}..{disclaimer_end}, len {})",
                out.len()
            )));
        }
        ctb_encrypt_in_place_no_padding(&mut out[disclaimer_start..disclaimer_end], &key, &iv)?;

        let pp_v4_start = extended_offsets.print_parameters_v4_offset as usize;
        let pp_v4_end = pp_v4_start.saturating_add(CTB_PRINT_PARAMETERS_V4_SIZE as usize);
        if pp_v4_end > out.len() {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES v4 parameter block out of range ({pp_v4_start}..{pp_v4_end}, len {})",
                out.len()
            )));
        }
        ctb_encrypt_in_place_no_padding(&mut out[pp_v4_start..pp_v4_end], &key, &iv)?;

        if build.version >= 5 {
            let resin_start = extended_offsets.resin_parameters_offset as usize;
            let resin_end = resin_start.saturating_add(resin_payload_len(&resin_payload) as usize);
            if resin_end > out.len() {
                return Err(SlicerV3Error::UnsupportedOutput(format!(
                    "CTB AES resin block out of range ({resin_start}..{resin_end}, len {})",
                    out.len()
                )));
            }
            ctb_encrypt_in_place_no_padding(&mut out[resin_start..resin_end], &key, &iv)?;
        }

        let hash = Sha256::digest(&out[settings_start..settings_end]);
        let signature = ctb_encrypt_padded_vec(hash.as_ref(), &key, &iv)?;

        push_u32(&mut out, 0x4220_52FA);
        push_u32(&mut out, 0);
        out.extend_from_slice(&signature);
        push_u32(&mut out, 0x6D42_32B3);
    }

    Ok(out)
}
