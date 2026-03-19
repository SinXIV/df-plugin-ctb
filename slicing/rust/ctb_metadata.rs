use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;
use base64::Engine;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use super::ctb_types::{
    CtbAesModel, CtbBuildModel, CtbResinModel, CtbTimingModel, CTB_DISCLAIMER_B64,
    DEFAULT_BINARY_THRESHOLD, DEFAULT_CTB_VERSION, DEFAULT_MACHINE_NAME, DEFAULT_RESIN_DENSITY,
    DEFAULT_RESIN_NAME, DEFAULT_RESIN_TYPE,
};

fn parse_json(metadata_json: &str) -> Option<Value> {
    serde_json::from_str::<Value>(metadata_json).ok()
}

pub(super) fn parse_threshold_from_metadata(metadata_json: &str) -> u8 {
    let Some(meta) = parse_json(metadata_json) else {
        return DEFAULT_BINARY_THRESHOLD;
    };

    let direct = meta
        .get("ctb")
        .and_then(|v| v.get("binaryThreshold"))
        .and_then(Value::as_u64);

    let nested = meta
        .get("export")
        .and_then(|v| v.get("ctb"))
        .and_then(|v| v.get("binaryThreshold"))
        .and_then(Value::as_u64);

    direct
        .or(nested)
        .map(|v| v.min(255) as u8)
        .unwrap_or(DEFAULT_BINARY_THRESHOLD)
}

pub(super) fn parse_timing_model_from_metadata(metadata_json: &str) -> CtbTimingModel {
    let Some(meta) = parse_json(metadata_json) else {
        return CtbTimingModel {
            normal_exposure_sec: 0.0,
            bottom_exposure_sec: 0.0,
            light_off_delay_sec: 0.0,
            bottom_light_off_delay_sec: 0.0,
            bottom_layer_count: 0,
            lift_distance_mm: 0.0,
            lift_speed_mm_min: 0.0,
            retract_speed_mm_min: 0.0,
            bottom_retract_speed_mm_min: 0.0,
            bottom_retract_speed2_mm_min: 0.0,
            bottom_retract_height2_mm: 0.0,
            transition_layer_count: 0,
            wait_time_before_cure_sec: 0.0,
            wait_time_after_cure_sec: 0.0,
            wait_time_after_lift_sec: 0.0,
        };
    };

    let material = meta.get("material").and_then(Value::as_object);
    let read_f32 = |key: &str| {
        material
            .and_then(|m| m.get(key))
            .and_then(Value::as_f64)
            .unwrap_or(0.0) as f32
    };
    let read_u32 = |key: &str| {
        material
            .and_then(|m| m.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32
    };

    CtbTimingModel {
        normal_exposure_sec: read_f32("normalExposureSec"),
        bottom_exposure_sec: read_f32("bottomExposureSec"),
        light_off_delay_sec: read_f32("lightOffDelaySec"),
        bottom_light_off_delay_sec: read_f32("bottomLightOffDelaySec"),
        bottom_layer_count: read_u32("bottomLayerCount"),
        lift_distance_mm: read_f32("liftDistanceMm"),
        lift_speed_mm_min: read_f32("liftSpeedMmMin"),
        retract_speed_mm_min: read_f32("retractSpeedMmMin"),
        bottom_retract_speed_mm_min: read_f32("bottomRetractSpeedMmMin"),
        bottom_retract_speed2_mm_min: read_f32("bottomRetractSpeed2MmMin"),
        bottom_retract_height2_mm: read_f32("bottomRetractHeight2Mm"),
        transition_layer_count: read_u32("transitionLayerCount"),
        wait_time_before_cure_sec: read_f32("waitTimeBeforeCureSec"),
        wait_time_after_cure_sec: read_f32("waitTimeAfterCureSec"),
        wait_time_after_lift_sec: read_f32("waitTimeAfterLiftSec"),
    }
}

fn parse_u32_meta(meta: &Value, path0: &str, path1: &str) -> Option<u32> {
    meta.get(path0)
        .and_then(|v| v.get(path1))
        .and_then(Value::as_u64)
        .map(|v| v as u32)
}

fn parse_str_meta(meta: &Value, path0: &str, path1: &str) -> Option<String> {
    meta.get(path0)
        .and_then(|v| v.get(path1))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn parse_bool_meta(meta: &Value, path0: &str, path1: &str) -> Option<bool> {
    meta.get(path0)
        .and_then(|v| v.get(path1))
        .and_then(Value::as_bool)
}

fn parse_f32_meta(meta: &Value, path0: &str, path1: &str) -> Option<f32> {
    meta.get(path0)
        .and_then(|v| v.get(path1))
        .and_then(Value::as_f64)
        .map(|v| v as f32)
}

fn parse_timestamp_meta(meta: &Value, path0: &str, path1: &str) -> Option<u32> {
    let node = meta.get(path0).and_then(|v| v.get(path1))?;
    if let Some(v) = node.as_u64() {
        return Some(v.min(u32::MAX as u64) as u32);
    }
    if let Some(v) = node.as_i64() {
        return Some(v.max(0).min(u32::MAX as i64) as u32);
    }
    if let Some(s) = node.as_str() {
        if let Ok(parsed) = s.trim().parse::<u64>() {
            return Some(parsed.min(u32::MAX as u64) as u32);
        }
    }
    None
}

fn unix_now_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

pub(super) fn parse_ctb_build_model_from_job(job: &SliceJobV3) -> CtbBuildModel {
    let mut version = DEFAULT_CTB_VERSION;
    let mut machine_name = DEFAULT_MACHINE_NAME.to_string();
    let mut bed_size_z_mm = (job.layer_height_mm.max(0.0) * (job.total_layers as f32)).max(0.0);
    let mut created_date_unix = unix_now_u32();
    let mut modified_date_unix = created_date_unix;
    let mut anti_alias_level = 1_u32;
    let mut layer_xor_key = 0_u32;
    let mut projector_type = if job.mirror_x || job.mirror_y { 1 } else { 0 };
    let mut per_layer_settings = false;

    if let Some(meta) = parse_json(&job.metadata_json) {
        let version_direct = parse_u32_meta(&meta, "ctb", "version");
        let version_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("version"))
            .and_then(Value::as_u64)
            .map(|v| v as u32);

        version = version_direct
            .or(version_nested)
            .unwrap_or(DEFAULT_CTB_VERSION)
            .clamp(2, 5);

        let machine_direct = parse_str_meta(&meta, "ctb", "machineName");
        let machine_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("machineName"))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        machine_name = machine_direct
            .or(machine_nested)
            .unwrap_or_else(|| DEFAULT_MACHINE_NAME.to_string());

        if let Some(v) = parse_str_meta(&meta, "ctb", "MachineName")
            .or_else(|| {
                meta.get("export")
                    .and_then(|v| v.get("ctb"))
                    .and_then(|v| v.get("MachineName"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| parse_str_meta(&meta, "printer", "machineName"))
            .or_else(|| parse_str_meta(&meta, "printer", "MachineName"))
            .or_else(|| parse_str_meta(&meta, "printer", "name"))
        {
            if !v.trim().is_empty() {
                machine_name = v;
            }
        }

        if let Some(v) = parse_f32_meta(&meta, "ctb", "bedSizeZ")
            .or_else(|| parse_f32_meta(&meta, "ctb", "BedSizeZ"))
            .or_else(|| {
                meta.get("export")
                    .and_then(|x| x.get("ctb"))
                    .and_then(|x| x.get("bedSizeZ"))
                    .and_then(Value::as_f64)
                    .map(|x| x as f32)
            })
            .or_else(|| {
                meta.get("export")
                    .and_then(|x| x.get("ctb"))
                    .and_then(|x| x.get("BedSizeZ"))
                    .and_then(Value::as_f64)
                    .map(|x| x as f32)
            })
            .or_else(|| {
                meta.get("printer")
                    .and_then(|x| x.get("buildVolumeMm"))
                    .and_then(|x| x.get("height"))
                    .and_then(Value::as_f64)
                    .map(|x| x as f32)
            })
            .or_else(|| parse_f32_meta(&meta, "printer", "bedSizeZ"))
            .or_else(|| parse_f32_meta(&meta, "printer", "BedSizeZ"))
        {
            if v.is_finite() && v > 0.0 {
                bed_size_z_mm = v;
            }
        }

        if let Some(v) = parse_timestamp_meta(&meta, "ctb", "createdDate")
            .or_else(|| parse_timestamp_meta(&meta, "ctb", "CreatedDate"))
            .or_else(|| {
                parse_timestamp_meta(&meta, "export", "createdDate")
                    .or_else(|| parse_timestamp_meta(&meta, "export", "CreatedDate"))
            })
        {
            created_date_unix = v;
        }

        if let Some(v) = parse_timestamp_meta(&meta, "ctb", "modifiedDate")
            .or_else(|| parse_timestamp_meta(&meta, "ctb", "ModifiedDate"))
            .or_else(|| {
                meta.get("export")
                    .and_then(|x| x.get("ctb"))
                    .and_then(|x| x.get("modifiedDate"))
                    .and_then(Value::as_u64)
                    .map(|x| x.min(u32::MAX as u64) as u32)
            })
            .or_else(|| {
                meta.get("export")
                    .and_then(|x| x.get("ctb"))
                    .and_then(|x| x.get("ModifiedDate"))
                    .and_then(Value::as_u64)
                    .map(|x| x.min(u32::MAX as u64) as u32)
            })
            .or_else(|| parse_timestamp_meta(&meta, "metadata", "modifiedDate"))
            .or_else(|| parse_timestamp_meta(&meta, "metadata", "ModifiedDate"))
        {
            modified_date_unix = v;
        }

        let aa_direct = parse_u32_meta(&meta, "ctb", "antiAliasLevel");
        let aa_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("antiAliasLevel"))
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        anti_alias_level = aa_direct.or(aa_nested).unwrap_or(1).clamp(1, 16);

        let key_direct = parse_u32_meta(&meta, "ctb", "layerXorKey");
        let key_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("layerXorKey"))
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        layer_xor_key = key_direct.or(key_nested).unwrap_or(0);

        let proj_direct = parse_u32_meta(&meta, "ctb", "projectorType");
        let proj_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("projectorType"))
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        projector_type = proj_direct.or(proj_nested).unwrap_or(projector_type);

        let pls_direct = parse_bool_meta(&meta, "ctb", "perLayerSettings");
        let pls_nested = meta
            .get("export")
            .and_then(|v| v.get("ctb"))
            .and_then(|v| v.get("perLayerSettings"))
            .and_then(Value::as_bool);
        per_layer_settings = pls_direct.or(pls_nested).unwrap_or(false);
    }

    anti_alias_level = anti_alias_level.max(1);

    CtbBuildModel {
        version,
        machine_name,
        bed_size_z_mm,
        created_date_unix,
        modified_date_unix,
        anti_alias_level,
        layer_xor_key,
        projector_type,
        per_layer_settings,
    }
}

pub(super) fn parse_ctb_resin_model_from_job(job: &SliceJobV3, machine_name: &str) -> CtbResinModel {
    let mut resin_name = DEFAULT_RESIN_NAME.to_string();
    let mut resin_type = DEFAULT_RESIN_TYPE.to_string();
    let mut resin_density = DEFAULT_RESIN_DENSITY;
    let mut color_rgba = [0x66, 0x66, 0x66, 0xff];

    if let Some(meta) = parse_json(&job.metadata_json) {
        let material = meta.get("material").and_then(Value::as_object);

        if let Some(v) = material.and_then(|m| m.get("name")).and_then(Value::as_str) {
            resin_name = v.to_string();
        }
        if let Some(v) = material
            .and_then(|m| m.get("resinType"))
            .and_then(Value::as_str)
        {
            resin_type = v.to_string();
        }
        if let Some(v) = material
            .and_then(|m| m.get("resinDensity"))
            .and_then(Value::as_f64)
        {
            resin_density = v as f32;
        }

        if let Some(v) = parse_str_meta(&meta, "ctb", "resinName").or_else(|| {
            meta.get("export")
                .and_then(|v| v.get("ctb"))
                .and_then(|v| v.get("resinName"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        }) {
            resin_name = v;
        }

        if let Some(v) = parse_str_meta(&meta, "ctb", "resinType").or_else(|| {
            meta.get("export")
                .and_then(|v| v.get("ctb"))
                .and_then(|v| v.get("resinType"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        }) {
            resin_type = v;
        }

        if let Some(v) = parse_u32_meta(&meta, "ctb", "resinColorR") {
            color_rgba[0] = v.min(255) as u8;
        }
        if let Some(v) = parse_u32_meta(&meta, "ctb", "resinColorG") {
            color_rgba[1] = v.min(255) as u8;
        }
        if let Some(v) = parse_u32_meta(&meta, "ctb", "resinColorB") {
            color_rgba[2] = v.min(255) as u8;
        }
        if let Some(v) = parse_u32_meta(&meta, "ctb", "resinColorA") {
            color_rgba[3] = v.min(255) as u8;
        }
    }

    if resin_name.is_empty() {
        resin_name = DEFAULT_RESIN_NAME.to_string();
    }
    if resin_type.is_empty() {
        resin_type = DEFAULT_RESIN_TYPE.to_string();
    }

    let _ = machine_name;

    CtbResinModel {
        resin_name,
        resin_type,
        resin_density,
        color_rgba,
    }
}

pub(super) fn parse_machine_software_version(version: u32) -> u32 {
    match version {
        2 => 0x0105_0000,
        3 => 0x0106_0300,
        4 => 0x0109_0000,
        5 => 0x0200_0000,
        _ => 0x0109_0000,
    }
}

pub(super) fn decode_embedded_disclaimer_bytes() -> Result<Vec<u8>, SlicerV3Error> {
    base64::engine::general_purpose::STANDARD
        .decode(CTB_DISCLAIMER_B64)
        .map_err(|e| {
            SlicerV3Error::UnsupportedOutput(format!(
                "failed to decode embedded CTB disclaimer bytes: {e}"
            ))
        })
}

pub(super) fn parse_ctb_aes_model_from_job(job: &SliceJobV3) -> CtbAesModel {
    let Some(meta) = parse_json(&job.metadata_json) else {
        return CtbAesModel {
            enabled: false,
            key: None,
            iv: None,
        };
    };

    let read_bool = |k: &str| {
        meta.get("ctb")
            .and_then(|v| v.get("aes"))
            .and_then(|v| v.get(k))
            .and_then(Value::as_bool)
            .or_else(|| {
                meta.get("export")
                    .and_then(|v| v.get("ctb"))
                    .and_then(|v| v.get("aes"))
                    .and_then(|v| v.get(k))
                    .and_then(Value::as_bool)
            })
    };

    let read_str = |k: &str| {
        meta.get("ctb")
            .and_then(|v| v.get("aes"))
            .and_then(|v| v.get(k))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                meta.get("export")
                    .and_then(|v| v.get("ctb"))
                    .and_then(|v| v.get("aes"))
                    .and_then(|v| v.get(k))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
    };

    let enabled = read_bool("enabled").unwrap_or(false);
    let key = read_str("keyBase64")
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok());
    let iv =
        read_str("ivBase64").and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok());

    CtbAesModel { enabled, key, iv }
}
