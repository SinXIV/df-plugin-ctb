// Encrypted CTB V5 format handling
use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;
use sha2::{Digest, Sha256};

use super::ctb_crypto::{ctb_default_key_iv, ctb_encrypt_in_place_no_padding};
use super::ctb_layout::{page_number_and_offset, push_f32, push_u16, push_u32, push_u64, push_u8};
use super::ctb_metadata::{
    decode_embedded_disclaimer_bytes, parse_ctb_build_model_from_job,
    parse_ctb_resin_model_from_job, parse_timing_model_from_metadata,
};
use super::ctb_preview::build_previews;
use super::ctb_preview::write_preview_record;
use super::ctb_types::{
    CtbPreparedLayer, CtbTimingModel, CTB_DISCLAIMER_SIZE, CTB_ENCRYPTED_HEADER_SIZE,
    CTB_ENCRYPTED_LAYER_DEF_SIZE, CTB_ENCRYPTED_SETTINGS_OFFSET, CTB_ENCRYPTED_SETTINGS_SIZE,
    CTB_MAGIC_V5_ENCRYPTED, CTB_PREVIEW_RECORD_SIZE,
};

fn write_ctb_encrypted_layer_def(
    out: &mut Vec<u8>,
    layer: &CtbPreparedLayer,
    position_z_mm: f32,
    exposure_sec: f32,
    light_off_sec: f32,
    timing: CtbTimingModel,
    layer_data_abs_offset: u64,
    is_bottom: bool,
) {
    let (page_number, layer_data_offset) = page_number_and_offset(layer_data_abs_offset);
    let clamp_non_negative = |value: f32| {
        if !value.is_finite() || value <= 0.0 {
            0.0
        } else {
            value
        }
    };

    let is_bottom_wait = (layer.index as u32) < timing.wait_time_bottom_layer_count;

    // Use bottom lift distance for bottom layers, normal for others
    let lift_distance = if is_bottom {
        timing.bottom_lift_distance_mm
    } else {
        timing.lift_distance_mm
    };
    let lift_distance2 = if is_bottom {
        timing.bottom_lift_distance2_mm
    } else {
        timing.lift_distance2_mm
    };
    let lift_speed = if is_bottom {
        timing.bottom_lift_speed_mm_min
    } else {
        timing.lift_speed_mm_min
    };
    let lift_speed2 = if is_bottom {
        timing.bottom_lift_speed2_mm_min
    } else {
        timing.lift_speed2_mm_min
    };
    let retract_speed = if is_bottom {
        timing.bottom_retract_speed_mm_min
    } else {
        timing.retract_speed_mm_min
    };
    let retract_speed2 = if is_bottom {
        timing.bottom_retract_speed2_mm_min
    } else {
        timing.retract_speed2_mm_min
    };
    let wait_time_after_cure = if is_bottom_wait {
        timing.bottom_wait_time_after_cure_sec
    } else {
        timing.wait_time_after_cure_sec
    };
    let wait_time_after_lift = if is_bottom_wait {
        timing.bottom_wait_time_after_lift_sec
    } else {
        timing.wait_time_after_lift_sec
    };
    let wait_time_before_cure = if is_bottom_wait {
        timing.bottom_wait_time_before_cure_sec
    } else {
        timing.wait_time_before_cure_sec
    };
    let projector_duty_cycle_pwm = if is_bottom {
        timing.bottom_layer_projector_duty_cycle_pwm
    } else {
        timing.projector_duty_cycle_pwm
    };


    let lift_height_1 = clamp_non_negative(lift_distance);
    let lift_height_2 = clamp_non_negative(lift_distance2);
    let lift_height_total = clamp_non_negative(lift_height_1 + lift_height_2);
    let retract_height_2 = clamp_non_negative(timing.retract_distance2_mm).min(lift_height_total);

    push_u32(out, CTB_ENCRYPTED_LAYER_DEF_SIZE);
    push_f32(out, position_z_mm);
    push_f32(out, exposure_sec);
    push_f32(out, light_off_sec);
    push_u32(out, layer_data_offset);
    push_u32(out, page_number);
    push_u32(out, layer.encoded.len() as u32);
    push_u32(out, 0);
    push_u32(out, 0);
    push_u32(out, 0);
    push_f32(out, lift_height_total);
    push_f32(out, clamp_non_negative(lift_speed));
    push_f32(out, lift_height_2);
    push_f32(out, clamp_non_negative(lift_speed2));
    push_f32(out, clamp_non_negative(retract_speed));
    push_f32(out, retract_height_2);
    push_f32(out, clamp_non_negative(retract_speed2));
    push_f32(out, clamp_non_negative(wait_time_after_cure));
    push_f32(out, clamp_non_negative(wait_time_after_lift));
    push_f32(out, clamp_non_negative(wait_time_before_cure));
    push_f32(out, clamp_non_negative(projector_duty_cycle_pwm as f32));
    push_u32(out, 0);
}

pub(super) fn build_ctb_encrypted_container_bytes_with_progress(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    on_progress: Option<&dyn Fn(u32, u32)>,
) -> Result<Vec<u8>, SlicerV3Error> {
    let timing = parse_timing_model_from_metadata(&job.metadata_json);
    let mut build = parse_ctb_build_model_from_job(job);
    build.version = 5;
    let resin = parse_ctb_resin_model_from_job(job, &build.machine_name);
    let previews = build_previews(job)?;
    let disclaimer_bytes = decode_embedded_disclaimer_bytes()?;

    let layer_count = prepared.len() as u32;
    let print_time_sec = {
        let mut total = 0.0_f32;
        for i in 0..prepared.len() {
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
    };

    let machine_name_bytes = build.machine_name.as_bytes().to_vec();
    let machine_name_size = machine_name_bytes.len() as u32;

    let mut resin_type_bytes = resin.resin_type.as_bytes().to_vec();
    let mut resin_name_bytes = resin.resin_name.as_bytes().to_vec();
    if resin_type_bytes.is_empty() {
        resin_type_bytes = b"Standard".to_vec();
    }
    if resin_name_bytes.is_empty() {
        resin_name_bytes = b"DragonFruit Resin".to_vec();
    }

    let mut out = vec![0u8; (CTB_ENCRYPTED_HEADER_SIZE + CTB_ENCRYPTED_SETTINGS_SIZE) as usize];

    let large_preview_offset = out.len() as u32;
    let large_preview_image_offset = large_preview_offset + CTB_PREVIEW_RECORD_SIZE;
    write_preview_record(
        &mut out,
        previews[0].width,
        previews[0].height,
        large_preview_image_offset,
        previews[0].encoded.len() as u32,
    );
    out.extend_from_slice(&previews[0].encoded);

    let small_preview_offset = out.len() as u32;
    let small_preview_image_offset = small_preview_offset + CTB_PREVIEW_RECORD_SIZE;
    write_preview_record(
        &mut out,
        previews[1].width,
        previews[1].height,
        small_preview_image_offset,
        previews[1].encoded.len() as u32,
    );
    out.extend_from_slice(&previews[1].encoded);

    let machine_name_offset = out.len() as u32;
    out.extend_from_slice(&machine_name_bytes);

    let disclaimer_offset = out.len() as u32;
    let mut disclaimer_padded = Vec::new();
    if disclaimer_bytes.len() >= CTB_DISCLAIMER_SIZE {
        disclaimer_padded.extend_from_slice(&disclaimer_bytes[..CTB_DISCLAIMER_SIZE]);
    } else {
        disclaimer_padded.extend_from_slice(&disclaimer_bytes);
        disclaimer_padded.resize(CTB_DISCLAIMER_SIZE, 0);
    }
    out.extend_from_slice(&disclaimer_padded);

    let resin_parameters_address = out.len() as u32;
    let resin_fixed_size = 40u32;
    let resin_type_address = resin_parameters_address + resin_fixed_size;
    let resin_name_address = resin_type_address + resin_type_bytes.len() as u32;
    let resin_machine_name_address = resin_name_address + resin_name_bytes.len() as u32;

    push_u32(&mut out, 0);
    push_u8(&mut out, resin.color_rgba[2]);
    push_u8(&mut out, resin.color_rgba[1]);
    push_u8(&mut out, resin.color_rgba[0]);
    push_u8(&mut out, resin.color_rgba[3]);
    push_u32(&mut out, resin_machine_name_address);
    push_u32(&mut out, resin_type_bytes.len() as u32);
    push_u32(&mut out, resin_type_address);
    push_u32(&mut out, resin_name_bytes.len() as u32);
    push_u32(&mut out, resin_name_address);
    push_u32(&mut out, machine_name_size);
    push_f32(&mut out, resin.resin_density);
    push_u32(&mut out, 0);
    out.extend_from_slice(&resin_type_bytes);
    out.extend_from_slice(&resin_name_bytes);
    out.extend_from_slice(&machine_name_bytes);

    let layer_pointers_offset = out.len() as u32;
    let layer_pointer_table_size = layer_count as usize * 16;
    let layer_pointers_table_start = out.len();
    out.resize(out.len() + layer_pointer_table_size, 0);

    let mut layer_pointer_entries: Vec<(u32, u32)> = Vec::with_capacity(layer_count as usize);
    let total_layers = prepared.len() as u32;
    for (idx, layer) in prepared.iter().enumerate() {
        let layer_def_abs = out.len() as u64;
        let layer_data_abs = layer_def_abs + CTB_ENCRYPTED_LAYER_DEF_SIZE as u64;
        let (layer_page, layer_offset) = page_number_and_offset(layer_def_abs);
        layer_pointer_entries.push((layer_offset, layer_page));

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

        write_ctb_encrypted_layer_def(
            &mut out,
            layer,
            (layer.index as f32 + 1.0) * job.layer_height_mm,
            exposure,
            light_off,
            timing,
            layer_data_abs,
            is_bottom,
        );
        out.extend_from_slice(&layer.encoded);

        if let Some(progress) = on_progress {
            progress((idx as u32) + 1, total_layers.max(1));
        }
    }

    push_u32(&mut out, 1_109_414_650);
    push_u32(&mut out, 0);

    let checksum_value: u64 = 0xCAFE_BABE;
    let checksum_hash = Sha256::digest(checksum_value.to_le_bytes());
    let mut signature = checksum_hash.to_vec();
    let (key, iv) = ctb_default_key_iv();
    ctb_encrypt_in_place_no_padding(&mut signature, &key, &iv)?;
    let signature_offset = out.len() as u32;
    out.extend_from_slice(&signature);
    push_u32(&mut out, 1_833_054_899);

    for (i, (layer_offset, layer_page)) in layer_pointer_entries.iter().enumerate() {
        let base = layer_pointers_table_start + i * 16;
        out[base..base + 4].copy_from_slice(&layer_offset.to_le_bytes());
        out[base + 4..base + 8].copy_from_slice(&layer_page.to_le_bytes());
        out[base + 8..base + 12].copy_from_slice(&CTB_ENCRYPTED_LAYER_DEF_SIZE.to_le_bytes());
        out[base + 12..base + 16].copy_from_slice(&0u32.to_le_bytes());
    }

    let mut settings = Vec::with_capacity(CTB_ENCRYPTED_SETTINGS_SIZE as usize);
    push_u64(&mut settings, checksum_value);
    push_u32(&mut settings, layer_pointers_offset);
    push_f32(&mut settings, job.build_width_mm);
    push_f32(&mut settings, job.build_depth_mm);
    push_f32(&mut settings, build.bed_size_z_mm.max(0.0));
    push_u32(&mut settings, build.created_date_unix);
    push_u32(&mut settings, build.modified_date_unix);
    push_f32(&mut settings, job.layer_height_mm * layer_count as f32);
    push_f32(&mut settings, job.layer_height_mm);
    push_f32(&mut settings, timing.normal_exposure_sec);
    push_f32(&mut settings, timing.bottom_exposure_sec);
    push_f32(&mut settings, timing.light_off_delay_sec);
    push_u32(&mut settings, timing.bottom_layer_count);
    push_u32(&mut settings, job.source_width_px);
    push_u32(&mut settings, job.source_height_px);
    push_u32(&mut settings, layer_count);
    push_u32(&mut settings, large_preview_offset);
    push_u32(&mut settings, small_preview_offset);
    push_u32(&mut settings, print_time_sec);
    push_u32(&mut settings, build.projector_type);
    // CTB print-parameter lift heights are TOTAL heights (stage1 + stage2).
    // UVTools/ChiTuBox derive stage1 lift height as (total_height - stage2_height).
    let bottom_lift_total_mm = timing.bottom_lift_distance_mm + timing.bottom_lift_distance2_mm;
    let lift_total_mm = timing.lift_distance_mm + timing.lift_distance2_mm;

    push_f32(&mut settings, bottom_lift_total_mm.max(0.0));
    push_f32(&mut settings, timing.bottom_lift_speed_mm_min);
    push_f32(&mut settings, lift_total_mm.max(0.0));
    push_f32(&mut settings, timing.lift_speed_mm_min);
    push_f32(&mut settings, timing.retract_speed_mm_min);
    push_f32(&mut settings, timing.retract_distance_mm);
    push_f32(&mut settings, timing.retract_distance2_mm);
    push_f32(&mut settings, timing.retract_speed2_mm_min);
    push_f32(&mut settings, timing.bottom_light_off_delay_sec);
    push_u32(&mut settings, 1);
    push_u16(&mut settings, timing.projector_duty_cycle_pwm); // Normal layer PWM
    push_u16(&mut settings, timing.bottom_layer_projector_duty_cycle_pwm); // Bottom layer PWM
    push_u32(&mut settings, build.layer_xor_key);
    // CTB encrypted slicer settings map these slots to:
    //   BottomLiftHeight2, BottomLiftSpeed2, LiftHeight2, LiftSpeed2,
    //   RetractHeight2, RetractSpeed2.
    push_f32(&mut settings, timing.bottom_lift_distance2_mm);
    push_f32(&mut settings, timing.bottom_lift_speed2_mm_min);
    push_f32(&mut settings, timing.lift_distance2_mm);
    push_f32(&mut settings, timing.lift_speed2_mm_min);
    push_f32(&mut settings, timing.retract_distance2_mm);
    push_f32(&mut settings, timing.retract_speed2_mm_min);
    push_f32(&mut settings, timing.wait_time_after_lift_sec);
    push_u32(&mut settings, machine_name_offset);
    push_u32(&mut settings, machine_name_size);
    push_u8(
        &mut settings,
        if build.anti_alias_level > 1 {
            0x0f
        } else {
            0x07
        },
    );
    push_u16(&mut settings, 0);
    push_u8(
        &mut settings,
        if build.per_layer_settings { 0x50 } else { 0x00 },
    );
    push_u32(&mut settings, build.modified_date_unix / 60);
    push_u32(&mut settings, build.anti_alias_level);
    push_f32(&mut settings, timing.wait_time_before_cure_sec);
    push_f32(&mut settings, timing.wait_time_after_lift_sec);
    push_u32(&mut settings, timing.transition_layer_count);
    push_f32(&mut settings, timing.bottom_retract_speed_mm_min);
    push_f32(&mut settings, timing.bottom_retract_speed2_mm_min);
    push_u32(&mut settings, 0);
    push_f32(&mut settings, timing.retract_distance_mm.max(0.0));
    push_u32(&mut settings, 0);
    push_f32(&mut settings, timing.retract_distance2_mm.max(0.0));
    push_f32(&mut settings, timing.wait_time_before_cure_sec);
    push_f32(&mut settings, timing.wait_time_after_lift_sec);
    push_f32(&mut settings, timing.wait_time_after_cure_sec);
    push_f32(&mut settings, timing.bottom_retract_height2_mm);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 4);
    push_u32(&mut settings, layer_count.saturating_sub(1));
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, disclaimer_offset);
    push_u32(&mut settings, CTB_DISCLAIMER_SIZE as u32);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, resin_parameters_address);
    push_u32(&mut settings, 0);
    push_u32(&mut settings, 0);

    if settings.len() != CTB_ENCRYPTED_SETTINGS_SIZE as usize {
        return Err(SlicerV3Error::UnsupportedOutput(format!(
            "internal encrypted CTB settings size mismatch: expected {}, got {}",
            CTB_ENCRYPTED_SETTINGS_SIZE,
            settings.len()
        )));
    }

    ctb_encrypt_in_place_no_padding(&mut settings, &key, &iv)?;
    let start = CTB_ENCRYPTED_SETTINGS_OFFSET as usize;
    let end = start + CTB_ENCRYPTED_SETTINGS_SIZE as usize;
    out[start..end].copy_from_slice(&settings);

    let mut header = Vec::with_capacity(CTB_ENCRYPTED_HEADER_SIZE as usize);
    push_u32(&mut header, CTB_MAGIC_V5_ENCRYPTED);
    push_u32(&mut header, CTB_ENCRYPTED_SETTINGS_SIZE);
    push_u32(&mut header, CTB_ENCRYPTED_SETTINGS_OFFSET);
    push_u32(&mut header, 0);
    push_u32(&mut header, 5);
    push_u32(&mut header, signature.len() as u32);
    push_u32(&mut header, signature_offset);
    push_u32(&mut header, 0);
    push_u16(&mut header, 1);
    push_u16(&mut header, 1);
    push_u32(&mut header, 0);
    push_u32(&mut header, 42);
    push_u32(&mut header, 0);
    if header.len() != CTB_ENCRYPTED_HEADER_SIZE as usize {
        return Err(SlicerV3Error::UnsupportedOutput(format!(
            "internal encrypted CTB header size mismatch: expected {}, got {}",
            CTB_ENCRYPTED_HEADER_SIZE,
            header.len()
        )));
    }
    out[..CTB_ENCRYPTED_HEADER_SIZE as usize].copy_from_slice(&header);

    Ok(out)
}
