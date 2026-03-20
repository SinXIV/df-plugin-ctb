// Non-encrypted CTB V5 format handling
use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;

use super::ctb_layout::{
    page_number_and_offset, push_bytes_padded, push_f32, push_u16, push_u32, push_u8,
};
use super::ctb_metadata::{
    decode_embedded_disclaimer_bytes, parse_ctb_build_model_from_job,
    parse_ctb_resin_model_from_job, parse_machine_software_version,
    parse_timing_model_from_metadata,
};
use super::ctb_preview::build_previews;
use super::ctb_preview::write_preview_record;
use super::ctb_types::{
    CtbBuildModel, CtbExtendedOffsets, CtbPreparedLayer, CtbPreviewOffsets, CtbResinModel,
    CtbResinPayload, CtbTimingModel, CTB_DISCLAIMER_SIZE, CTB_HEADER_SIZE, CTB_LAYER_DEF_EX_SIZE,
    CTB_LAYER_DEF_SIZE, CTB_MAGIC_V2_V3, CTB_MAGIC_V4_V5, CTB_PREVIEW_RECORD_SIZE,
    CTB_PRINT_PARAMETERS_SIZE, CTB_PRINT_PARAMETERS_V4_RESERVED_SIZE, CTB_PRINT_PARAMETERS_V4_SIZE,
    CTB_SLICER_INFO_FIXED_SIZE,
};

fn ctb_magic_for_version(version: u32) -> u32 {
    if version == 4 {
        CTB_MAGIC_V4_V5
    } else {
        CTB_MAGIC_V2_V3
    }
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
    push_f32(out, timing.lift_distance2_mm);
    push_f32(out, timing.lift_speed2_mm_min);
    push_f32(out, timing.retract_speed_mm_min);
    push_f32(out, timing.retract_distance_mm);
    push_f32(out, timing.retract_distance2_mm);
    push_f32(out, timing.retract_speed2_mm_min);
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
    push_f32(out, timing.retract_distance_mm);
    push_f32(out, timing.retract_distance2_mm);
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

    push_u32(out, build.modified_date_unix / 60);
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
    push_f32(out, timing.retract_distance_mm.max(0.0));
    push_u32(out, 0);
    push_f32(out, timing.retract_distance2_mm.max(0.0));
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

pub(super) fn build_ctb_container_bytes_with_progress(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    on_progress: Option<&dyn Fn(u32, u32)>,
) -> Result<Vec<u8>, SlicerV3Error> {
    let timing = parse_timing_model_from_metadata(&job.metadata_json);
    let build = parse_ctb_build_model_from_job(job);
    let resin = parse_ctb_resin_model_from_job(job, &build.machine_name);

    let previews = build_previews(job)?;

    let mut machine_name_bytes = build.machine_name.as_bytes().to_vec();
    if build.version >= 5 && !machine_name_bytes.ends_with(&[0]) {
        machine_name_bytes.push(0);
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

    let resin_payload = prepare_resin_payload(&build, &resin, false);

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

    let magic = ctb_magic_for_version(build.version);
    let print_time_sec = compute_print_time_seconds(prepared.len(), timing);

    let preview_offsets = CtbPreviewOffsets {
        large_record_offset: large_preview_record_offset,
        small_record_offset: small_preview_record_offset,
    };

    let mut out = Vec::new();
    write_ctb_header(
        &mut out,
        magic,
        build.version,
        job,
        layer_count,
        timing,
        &build,
        preview_offsets.clone(),
        print_parameters_offset,
        layers_definition_offset + layer_defs_data.len() as u32,
        print_time_sec,
        slicer_offset,
        slicer_size,
    );

    assert_eq!(out.len(), CTB_HEADER_SIZE as usize);

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
    assert_eq!(
        out.len(),
        print_parameters_offset as usize + CTB_PRINT_PARAMETERS_SIZE as usize
    );

    write_ctb_slicer_info_fixed(
        &mut out,
        &build,
        timing,
        machine_name_offset,
        machine_name_size,
        extended_offsets.print_parameters_v4_offset,
    );
    assert_eq!(out.len(), slicer_offset as usize + slicer_size as usize);

    out.extend_from_slice(&machine_name_bytes);
    assert_eq!(
        out.len(),
        machine_name_offset as usize + machine_name_size as usize
    );

    if build.version >= 4 {
        push_bytes_padded(&mut out, &disclaimer_bytes, CTB_DISCLAIMER_SIZE);
        assert_eq!(
            out.len(),
            extended_offsets.disclaimer_offset as usize + CTB_DISCLAIMER_SIZE
        );

        write_ctb_print_parameters_v4(&mut out, timing, layer_count, extended_offsets);
        assert_eq!(
            out.len(),
            extended_offsets.print_parameters_v4_offset as usize
                + CTB_PRINT_PARAMETERS_V4_SIZE as usize
        );

        if build.version >= 5 {
            write_ctb_resin_parameters(
                &mut out,
                extended_offsets.resin_parameters_offset,
                &resin_payload,
                &resin,
            );
            assert_eq!(
                out.len(),
                extended_offsets.resin_parameters_offset as usize
                    + resin_payload_len(&resin_payload) as usize
            );
        }
    }

    assert_eq!(out.len(), layers_definition_offset as usize);

    let total_prepared = prepared.len() as u32;
    for (idx, layer) in prepared.iter().enumerate() {
        let layer_data_abs = (layers_definition_offset as u64)
            + (layer_defs_data.len() as u64)
            + if build.version >= 4 {
                if build.version >= 5 {
                    CTB_LAYER_DEF_EX_SIZE as u64
                } else {
                    CTB_LAYER_DEF_SIZE as u64
                }
            } else {
                CTB_LAYER_DEF_SIZE as u64
            };

        let mut layer_def_bytes = Vec::new();

        write_layer_def(
            &mut layer_def_bytes,
            layer,
            (layer.index as f32 + 1.0) * job.layer_height_mm,
            if (layer.index as u32) < timing.bottom_layer_count {
                timing.bottom_exposure_sec
            } else {
                timing.normal_exposure_sec
            },
            if (layer.index as u32) < timing.bottom_layer_count {
                timing.bottom_light_off_delay_sec
            } else {
                timing.light_off_delay_sec
            },
            layer_data_abs,
        );

        if build.version >= 4 {
            if build.version >= 5 {
                write_layer_def_ex(&mut layer_ex_and_payload, layer, &layer_def_bytes, timing);
            } else {
                layer_defs_data.extend_from_slice(&layer_def_bytes);
            }
        } else {
            layer_defs_data.extend_from_slice(&layer_def_bytes);
        }

        layer_ex_and_payload.extend_from_slice(&layer.encoded);

        if let Some(progress) = on_progress {
            progress((idx as u32) + 1, total_prepared.max(1));
        }
    }

    out.extend_from_slice(&layer_defs_data);
    out.extend_from_slice(&layer_ex_and_payload);

    Ok(out)
}
