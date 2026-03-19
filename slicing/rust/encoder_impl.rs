use crate::encoders::FormatEncoder;
use crate::engine::SlicerV3Error;
use crate::types::{LayerAreaStatsV3, RenderedLayersV3, SliceJobV3};
use serde_json::{json, Value};
use std::path::Path;

pub struct CtbPluginEncoder;

pub fn create_plugin_encoder() -> Vec<Box<dyn FormatEncoder>> {
    vec![Box::new(CtbPluginEncoder)]
}

const DEFAULT_BINARY_THRESHOLD: u8 = 127;
const CTB_DRAFT_MAGIC: &[u8; 8] = b"DFCTBDR1";
const CTB_DRAFT_VERSION: u32 = 2;
const CTB_DRAFT_HEADER_SIZE: u32 = 80;
const CTB_DRAFT_SECTION_ENTRY_SIZE: u32 = 20;
const SECTION_ID_META: [u8; 4] = *b"META";
const SECTION_ID_LUT0: [u8; 4] = *b"LUT0";
const SECTION_ID_LAYR: [u8; 4] = *b"LAYR";

#[derive(Debug, Clone)]
struct CtbPreparedLayer {
    index: usize,
    source_len: usize,
    encoded: Vec<u8>,
    lit_pixels: u32,
}

#[derive(Debug, Clone, Copy)]
struct CtbTimingModel {
    normal_exposure_sec: f32,
    bottom_exposure_sec: f32,
    bottom_layer_count: u32,
    lift_distance_mm: f32,
    lift_speed_mm_min: f32,
    retract_speed_mm_min: f32,
}

#[derive(Debug, Clone)]
struct DraftSection {
    id: [u8; 4],
    bytes: Vec<u8>,
}

fn rle_encode_mask_row_major(mask: &[u8]) -> Vec<u8> {
    if mask.is_empty() {
        return Vec::new();
    }

    // CTB-style run format (clean-room behavior mapping):
    // - First byte stores 7-bit grayscale value (value >> 1).
    // - High bit indicates whether a run-length field follows.
    // - Run-length field uses variable-length prefixes for larger spans.
    //
    // For binary masks (0 / 255), this maps to values 0x00 and 0x7f.
    let mut out = Vec::with_capacity(mask.len() / 2);
    let mut run_value = mask[0];
    let mut run_len: u32 = 1;

    for &px in &mask[1..] {
        if px == run_value {
            run_len = run_len.saturating_add(1);
            continue;
        }

        push_ctb_style_run(&mut out, run_len, run_value);
        run_value = px;
        run_len = 1;
    }

    push_ctb_style_run(&mut out, run_len, run_value);
    out
}

fn push_ctb_style_run(out: &mut Vec<u8>, len: u32, value_8bit: u8) {
    if len == 0 {
        return;
    }

    let mut code = value_8bit >> 1; // 8-bit grayscale -> 7-bit storage
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

    // Highest currently-supported span envelope in known CTB family layouts.
    let clamped = len.min(0x0fff_ffff);
    out.push(((clamped >> 24) as u8) | 0xe0);
    out.push((clamped >> 16) as u8);
    out.push((clamped >> 8) as u8);
    out.push(clamped as u8);
}

fn normalize_to_binary_mask(mask: &[u8], threshold: u8) -> (Vec<u8>, u32) {
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

fn parse_threshold_from_metadata(metadata_json: &str) -> u8 {
    let Ok(meta) = serde_json::from_str::<Value>(metadata_json) else {
        return DEFAULT_BINARY_THRESHOLD;
    };

    // Preferred knobs (kept narrow and explicit to avoid accidental collisions):
    // - metadata.ctb.binaryThreshold
    // - metadata.export.ctb.binaryThreshold
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

fn parse_experimental_serialize_from_metadata(metadata_json: &str) -> bool {
    let Ok(meta) = serde_json::from_str::<Value>(metadata_json) else {
        return false;
    };

    let direct = meta
        .get("ctb")
        .and_then(|v| v.get("experimentalSerialize"))
        .and_then(Value::as_bool);

    let nested = meta
        .get("export")
        .and_then(|v| v.get("ctb"))
        .and_then(|v| v.get("experimentalSerialize"))
        .and_then(Value::as_bool);

    direct.or(nested).unwrap_or(false)
}

fn parse_timing_model_from_metadata(metadata_json: &str) -> CtbTimingModel {
    let Ok(meta) = serde_json::from_str::<Value>(metadata_json) else {
        return CtbTimingModel {
            normal_exposure_sec: 0.0,
            bottom_exposure_sec: 0.0,
            bottom_layer_count: 0,
            lift_distance_mm: 0.0,
            lift_speed_mm_min: 0.0,
            retract_speed_mm_min: 0.0,
        };
    };

    let material = meta.get("material").and_then(Value::as_object);
    let read_f32 = |key: &str| {
        material
            .and_then(|m| m.get(key))
            .and_then(Value::as_f64)
            .unwrap_or(0.0) as f32
    };
    let bottom_layer_count = material
        .and_then(|m| m.get("bottomLayerCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;

    CtbTimingModel {
        normal_exposure_sec: read_f32("normalExposureSec"),
        bottom_exposure_sec: read_f32("bottomExposureSec"),
        bottom_layer_count,
        lift_distance_mm: read_f32("liftDistanceMm"),
        lift_speed_mm_min: read_f32("liftSpeedMmMin"),
        retract_speed_mm_min: read_f32("retractSpeedMmMin"),
    }
}

fn prepare_layers_for_ctb(raw_masks: &[Vec<u8>], threshold: u8) -> Vec<CtbPreparedLayer> {
    raw_masks
        .iter()
        .enumerate()
        .map(|(index, layer)| {
            let (binary, lit_pixels) = normalize_to_binary_mask(layer, threshold);
            let encoded = rle_encode_mask_row_major(&binary);
            CtbPreparedLayer {
                index,
                source_len: layer.len(),
                encoded,
                lit_pixels,
            }
        })
        .collect()
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_f32(out: &mut Vec<u8>, value: f32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_section_entry(out: &mut Vec<u8>, section_id: [u8; 4], offset: u64, size: u64) {
    out.extend_from_slice(&section_id);
    push_u64(out, offset);
    push_u64(out, size);
}

fn build_layer_table_section(prepared: &[CtbPreparedLayer]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prepared.len() * 24);
    let mut encoded_offset: u64 = 0;

    for layer in prepared {
        push_u32(&mut out, layer.index as u32);
        push_u32(&mut out, layer.source_len as u32);
        push_u32(&mut out, layer.lit_pixels);
        push_u32(&mut out, layer.encoded.len() as u32);
        push_u64(&mut out, encoded_offset);
        encoded_offset = encoded_offset.saturating_add(layer.encoded.len() as u64);
    }

    out
}

fn build_metadata_section(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    threshold: u8,
    timing: CtbTimingModel,
) -> Result<Vec<u8>, SlicerV3Error> {
    let source_bytes: u64 = prepared.iter().map(|l| l.source_len as u64).sum();
    let encoded_bytes: u64 = prepared.iter().map(|l| l.encoded.len() as u64).sum();
    let lit_pixels: u64 = prepared.iter().map(|l| l.lit_pixels as u64).sum();

    let metadata = json!({
        "container": {
            "kind": "ctb-draft",
            "version": CTB_DRAFT_VERSION,
            "experimental": true,
        },
        "raster": {
            "widthPx": job.source_width_px,
            "heightPx": job.source_height_px,
            "layers": prepared.len(),
            "binaryThreshold": threshold,
            "sourceBytes": source_bytes,
            "encodedBytes": encoded_bytes,
            "litPixels": lit_pixels,
        },
        "timing": {
            "normalExposureSec": timing.normal_exposure_sec,
            "bottomExposureSec": timing.bottom_exposure_sec,
            "bottomLayerCount": timing.bottom_layer_count,
            "liftDistanceMm": timing.lift_distance_mm,
            "liftSpeedMmMin": timing.lift_speed_mm_min,
            "retractSpeedMmMin": timing.retract_speed_mm_min,
        },
        "build": {
            "buildWidthMm": job.build_width_mm,
            "buildDepthMm": job.build_depth_mm,
            "layerHeightMm": job.layer_height_mm,
            "mirrorX": job.mirror_x,
            "mirrorY": job.mirror_y,
            "antiAliasingLevel": job.anti_aliasing_level,
        }
    });

    Ok(serde_json::to_vec(&metadata)?)
}

fn build_experimental_container_bytes(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    threshold: u8,
) -> Result<Vec<u8>, SlicerV3Error> {
    let timing = parse_timing_model_from_metadata(&job.metadata_json);
    let section_meta = DraftSection {
        id: SECTION_ID_META,
        bytes: build_metadata_section(job, prepared, threshold, timing)?,
    };
    let section_lut = DraftSection {
        id: SECTION_ID_LUT0,
        bytes: build_layer_table_section(prepared),
    };
    let section_layers = DraftSection {
        id: SECTION_ID_LAYR,
        bytes: prepared
            .iter()
            .flat_map(|l| l.encoded.iter().copied())
            .collect(),
    };

    let sections = vec![section_meta, section_lut, section_layers];
    let section_count = sections.len() as u32;
    let section_table_size = section_count.saturating_mul(CTB_DRAFT_SECTION_ENTRY_SIZE);
    let section_table_offset = CTB_DRAFT_HEADER_SIZE as u64;
    let payload_offset = section_table_offset.saturating_add(section_table_size as u64);

    let payload_size: u64 = sections.iter().map(|s| s.bytes.len() as u64).sum();
    let total_size = payload_offset.saturating_add(payload_size);

    let mut out = Vec::with_capacity(total_size as usize);

    // Header (80 bytes)
    out.extend_from_slice(CTB_DRAFT_MAGIC); // 8
    push_u32(&mut out, CTB_DRAFT_VERSION); // 12
    push_u32(&mut out, CTB_DRAFT_HEADER_SIZE); // 16
    push_u32(&mut out, job.source_width_px); // 20
    push_u32(&mut out, job.source_height_px); // 24
    push_u32(&mut out, prepared.len() as u32); // 28
    out.push(threshold); // 29
    out.extend_from_slice(&[0, 0, 0]); // 32 reserved
    push_f32(&mut out, job.layer_height_mm); // 36
    push_f32(&mut out, job.build_width_mm); // 40
    push_f32(&mut out, job.build_depth_mm); // 44
    push_u32(&mut out, section_count); // 48
    push_u64(&mut out, section_table_offset); // 56
    push_u64(&mut out, payload_offset); // 64
    push_u64(&mut out, total_size); // 72
    push_u64(&mut out, 0); // 80 reserved

    // Section table + payload
    let mut running_payload_offset = payload_offset;
    for section in &sections {
        push_section_entry(
            &mut out,
            section.id,
            running_payload_offset,
            section.bytes.len() as u64,
        );
        running_payload_offset = running_payload_offset.saturating_add(section.bytes.len() as u64);
    }
    for section in sections {
        out.extend_from_slice(&section.bytes);
    }

    if out.is_empty() {
        return Err(SlicerV3Error::UnsupportedOutput(
            "failed to build experimental CTB container bytes".to_string(),
        ));
    }

    Ok(out)
}

impl FormatEncoder for CtbPluginEncoder {
    fn output_format(&self) -> &'static str {
        ".ctb"
    }

    fn requires_png_layers(&self) -> bool {
        false
    }

    fn requires_raw_mask_layers(&self) -> bool {
        true
    }

    fn encode_container_from_rendered_layers(
        &self,
        job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        _layer_area_stats: &[LayerAreaStatsV3],
    ) -> Result<Vec<u8>, SlicerV3Error> {
        let Some(raw_masks) = rendered_layers.raw_mask_layers.as_ref() else {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "raw mask layers are required for CTB encoding".to_string(),
            ));
        };

        if raw_masks.is_empty() {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "no rendered layers were provided for CTB encoding".to_string(),
            ));
        }

        let expected_pixels = (job.source_width_px as usize).saturating_mul(job.source_height_px as usize);
        for (idx, layer) in raw_masks.iter().enumerate() {
            if layer.len() != expected_pixels {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB layer {idx} size mismatch: expected {expected_pixels} bytes, got {}",
                    layer.len()
                )));
            }
        }

        let threshold = parse_threshold_from_metadata(&job.metadata_json);
        let prepared = prepare_layers_for_ctb(raw_masks, threshold);

        let encoded_bytes: usize = prepared.iter().map(|l| l.encoded.len()).sum();
        let source_bytes: usize = prepared.iter().map(|l| l.source_len).sum();
        let lit_pixels: u64 = prepared.iter().map(|l| l.lit_pixels as u64).sum();
        let experimental_serialize = parse_experimental_serialize_from_metadata(&job.metadata_json);

        if experimental_serialize {
            return build_experimental_container_bytes(job, &prepared, threshold);
        }

        Err(SlicerV3Error::UnsupportedOutput(
            format!(
                "CTB container serialization is not implemented yet (prepared {} layer(s), {} -> {} bytes RLE, lit pixels: {}, threshold: {}). To emit the experimental binary container for validation, set metadata.ctb.experimentalSerialize=true",
                prepared.len(),
                source_bytes,
                encoded_bytes,
                lit_pixels,
                threshold,
            ),
        ))
    }

    fn encode_container_to_path(
        &self,
        job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        layer_area_stats: &[LayerAreaStatsV3],
        output_path: &Path,
    ) -> Result<(), SlicerV3Error> {
        let bytes = self.encode_container_from_rendered_layers(job, rendered_layers, layer_area_stats)?;
        std::fs::write(output_path, bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_experimental_container_bytes, normalize_to_binary_mask,
        parse_experimental_serialize_from_metadata, parse_threshold_from_metadata,
        push_ctb_style_run, rle_encode_mask_row_major, CtbPreparedLayer, CTB_DRAFT_MAGIC,
        CTB_DRAFT_HEADER_SIZE, SECTION_ID_LAYR, SECTION_ID_LUT0, SECTION_ID_META,
    };
    use crate::types::SliceJobV3;

    fn make_test_job() -> SliceJobV3 {
        SliceJobV3 {
            output_format: ".ctb".to_string(),
            source_width_px: 4,
            source_height_px: 4,
            width_px: 4,
            height_px: 4,
            build_width_mm: 10.0,
            build_depth_mm: 20.0,
            layer_height_mm: 0.05,
            total_layers: 2,
            export_thumbnail_png_base64: None,
            png_compression_strategy: "balanced".to_string(),
            container_compression_level: 2,
            anti_aliasing_level: "Off".to_string(),
            aa_on_supports: false,
            mirror_x: false,
            mirror_y: false,
            triangles_xyz: vec![],
            metadata_json: "{}".to_string(),
        }
    }

    #[test]
    fn binary_mask_thresholds_values() {
        let (masked, lit) = normalize_to_binary_mask(&[0, 12, 127, 128, 255], 127);
        assert_eq!(masked, vec![0, 0, 0, 255, 255]);
        assert_eq!(lit, 2);
    }

    #[test]
    fn rle_encodes_simple_runs() {
        // Runs: 2x0, 3x255, 1x0 in CTB-style packetization.
        let encoded = rle_encode_mask_row_major(&[0, 0, 255, 255, 255, 0]);
        assert_eq!(encoded, vec![0x80, 0x02, 0xff, 0x03, 0x00]);
    }

    #[test]
    fn rle_handles_long_runs_above_u8() {
        let input = vec![255u8; 300];
        let encoded = rle_encode_mask_row_major(&input);
        // One run, length=300 => 0x012C with 0x80-prefixed 2-byte run length.
        assert_eq!(encoded, vec![0xff, 0x81, 0x2c]);
    }

    #[test]
    fn ctb_run_encoder_supports_4byte_span_prefix() {
        let mut out = Vec::new();
        push_ctb_style_run(&mut out, 0x2A_BC_DE_u32, 255);

        // code(255>>1) with run-flag + 4-byte run prefix.
        assert_eq!(out[0], 0xff);
        assert_eq!(out[1] & 0xE0, 0xE0);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn metadata_threshold_defaults_when_missing_or_invalid() {
        assert_eq!(parse_threshold_from_metadata("{}"), 127);
        assert_eq!(parse_threshold_from_metadata("not-json"), 127);
    }

    #[test]
    fn metadata_threshold_reads_supported_paths() {
        let direct = r#"{ "ctb": { "binaryThreshold": 180 } }"#;
        let nested = r#"{ "export": { "ctb": { "binaryThreshold": 200 } } }"#;

        assert_eq!(parse_threshold_from_metadata(direct), 180);
        assert_eq!(parse_threshold_from_metadata(nested), 200);
    }

    #[test]
    fn experimental_serialize_flag_reads_supported_paths() {
        let direct = r#"{ "ctb": { "experimentalSerialize": true } }"#;
        let nested = r#"{ "export": { "ctb": { "experimentalSerialize": true } } }"#;
        let no_flag = r#"{ "ctb": { "binaryThreshold": 123 } }"#;

        assert!(parse_experimental_serialize_from_metadata(direct));
        assert!(parse_experimental_serialize_from_metadata(nested));
        assert!(!parse_experimental_serialize_from_metadata(no_flag));
    }

    #[test]
    fn experimental_container_has_expected_header_and_magic() {
        let job = make_test_job();
        let prepared = vec![
            CtbPreparedLayer {
                index: 0,
                source_len: 16,
                encoded: vec![2, 0, 255],
                lit_pixels: 1,
            },
            CtbPreparedLayer {
                index: 1,
                source_len: 16,
                encoded: vec![1, 0, 0],
                lit_pixels: 0,
            },
        ];

        let bytes = build_experimental_container_bytes(&job, &prepared, 127).expect("container should build");
        assert!(bytes.len() > 64);
        assert_eq!(&bytes[0..8], CTB_DRAFT_MAGIC);

        // header offsets:
        // 0..8 magic
        // 8..12 version
        // 16..20 width
        // 20..24 height
        // 24..28 layer_count
        let width = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let height = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let layers = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        assert_eq!(width, 4);
        assert_eq!(height, 4);
        assert_eq!(layers, 2);
    }

    #[test]
    fn experimental_container_writes_expected_section_ids() {
        let job = make_test_job();
        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
            lit_pixels: 1,
        }];

        let bytes = build_experimental_container_bytes(&job, &prepared, 127).expect("container should build");
        let table_offset = CTB_DRAFT_HEADER_SIZE as usize;
        let first = &bytes[table_offset..table_offset + 4];
        let second = &bytes[table_offset + 20..table_offset + 24];
        let third = &bytes[table_offset + 40..table_offset + 44];

        assert_eq!(first, SECTION_ID_META);
        assert_eq!(second, SECTION_ID_LUT0);
        assert_eq!(third, SECTION_ID_LAYR);
    }
}
