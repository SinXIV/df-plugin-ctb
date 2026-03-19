use crate::encoders::FormatEncoder;
use crate::engine::SlicerV3Error;
use crate::types::{LayerAreaStatsV3, RenderedLayersV3, SliceJobV3};
use serde_json::Value;
use std::path::Path;

pub struct CtbPluginEncoder;

pub fn create_plugin_encoder() -> Vec<Box<dyn FormatEncoder>> {
    vec![Box::new(CtbPluginEncoder)]
}

const DEFAULT_BINARY_THRESHOLD: u8 = 127;
const EXPERIMENTAL_CONTAINER_MAGIC: &[u8; 8] = b"DFCTBEX1";
const EXPERIMENTAL_CONTAINER_VERSION: u32 = 1;

#[derive(Debug, Clone)]
struct CtbPreparedLayer {
    index: usize,
    source_len: usize,
    encoded: Vec<u8>,
    lit_pixels: u32,
}

fn rle_encode_mask_row_major(mask: &[u8]) -> Vec<u8> {
    if mask.is_empty() {
        return Vec::new();
    }

    // Run packet: [run_len_le_u16, run_value_u8].
    // A 16-bit run length avoids pathological expansion on large uniform spans.
    let mut out = Vec::with_capacity(mask.len() / 3);
    let mut run_value = mask[0];
    let mut run_len: u16 = 1;

    for &px in &mask[1..] {
        if px == run_value && run_len < u16::MAX {
            run_len = run_len.saturating_add(1);
            continue;
        }

        out.extend_from_slice(&run_len.to_le_bytes());
        out.push(run_value);
        run_value = px;
        run_len = 1;
    }

    out.extend_from_slice(&run_len.to_le_bytes());
    out.push(run_value);
    out
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

fn build_experimental_container_bytes(
    job: &SliceJobV3,
    prepared: &[CtbPreparedLayer],
    threshold: u8,
) -> Result<Vec<u8>, SlicerV3Error> {
    let mut out = Vec::new();

    // Header
    out.extend_from_slice(EXPERIMENTAL_CONTAINER_MAGIC);
    push_u32(&mut out, EXPERIMENTAL_CONTAINER_VERSION);
    push_u32(&mut out, job.source_width_px);
    push_u32(&mut out, job.source_height_px);
    push_u32(&mut out, prepared.len() as u32);
    out.push(threshold);
    out.extend_from_slice(&[0, 0, 0]); // reserved
    push_f32(&mut out, job.layer_height_mm);
    push_f32(&mut out, job.build_width_mm);
    push_f32(&mut out, job.build_depth_mm);
    push_u32(&mut out, prepared.len() as u32); // table entry count

    // Table entries (offsets are relative to payload start).
    let mut payload_offset: u64 = 0;
    for layer in prepared {
        push_u32(&mut out, layer.index as u32);
        push_u32(&mut out, layer.source_len as u32);
        push_u32(&mut out, layer.lit_pixels);
        push_u32(&mut out, layer.encoded.len() as u32);
        push_u64(&mut out, payload_offset);
        payload_offset = payload_offset.saturating_add(layer.encoded.len() as u64);
    }

    // Payload block
    for layer in prepared {
        out.extend_from_slice(&layer.encoded);
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
        rle_encode_mask_row_major, CtbPreparedLayer, EXPERIMENTAL_CONTAINER_MAGIC,
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
        // Runs: 2x0, 3x255, 1x0
        let encoded = rle_encode_mask_row_major(&[0, 0, 255, 255, 255, 0]);
        assert_eq!(encoded, vec![2, 0, 0, 3, 0, 255, 1, 0, 0]);
    }

    #[test]
    fn rle_handles_long_runs_above_u8() {
        let input = vec![255u8; 300];
        let encoded = rle_encode_mask_row_major(&input);
        // One run, length=300 => 0x012C (little-endian [44,1]), value=255
        assert_eq!(encoded, vec![44, 1, 255]);
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
        assert!(bytes.len() > 32);
        assert_eq!(&bytes[0..8], EXPERIMENTAL_CONTAINER_MAGIC);

        // header offsets:
        // 0..8 magic
        // 8..12 version
        // 12..16 width
        // 16..20 height
        // 20..24 layer_count
        let width = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let height = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let layers = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        assert_eq!(width, 4);
        assert_eq!(height, 4);
        assert_eq!(layers, 2);
    }
}
