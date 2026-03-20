mod ctb_crypto;
mod ctb_layout;
mod ctb_metadata;
mod ctb_preview;
mod ctb_types;

use crate::encoders::FormatEncoder;
use crate::encoders::RawMaskStreamEncoder;
use crate::engine::SlicerV3Error;
use crate::types::{LayerAreaStatsV3, RenderedLayersV3, SliceJobV3};
use ctb_layout::{
    build_ctb_container_bytes, build_ctb_container_bytes_with_progress,
    encode_single_ctb_empty_layer, encode_single_ctb_layer_from_raw_mask, prepare_layers_for_ctb,
    prepare_layers_for_ctb_with_progress,
};
use ctb_metadata::{parse_ctb_build_model_from_job, parse_threshold_from_metadata};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

#[cfg(test)]
use ctb_layout::{
    ctb_layer_rle_xor, normalize_to_binary_mask, push_ctb_run, rle_encode_mask_row_major,
};
#[cfg(test)]
use ctb_metadata::decode_embedded_disclaimer_bytes;
#[cfg(test)]
use ctb_types::{CtbPreparedLayer, CTB_DISCLAIMER_SIZE, CTB_HEADER_SIZE};

pub struct CtbPluginEncoder;

fn choose_ctb_encode_threads() -> usize {
    let hw = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let env = std::env::var("DF_V3_CTB_ENCODE_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(hw);
    env.clamp(1, hw)
}

fn cap_ctb_encode_workers_for_mask_bytes(requested: usize, expected_pixels: usize) -> usize {
    let bytes_per_mask = expected_pixels;
    let mut capped = requested.max(1);

    // Optional override: memory budget for in-flight CTB raw masks (MB).
    // Example: 1024 means allow about 1 GB worth of queued/working masks.
    let budget_override = std::env::var("DF_V3_MAX_CTB_INFLIGHT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 64)
        .map(|mb| mb.saturating_mul(1024 * 1024));

    if let Some(budget_bytes) = budget_override {
        let allowed = (budget_bytes / bytes_per_mask.max(1)).max(1);
        capped = capped.min(allowed);
    }

    // Each encoder worker can hold a full raw mask plus encoded output buffers.
    // Be conservative for massive layers to prevent allocation failures.
    if budget_override.is_none() {
        if bytes_per_mask >= 48 * 1024 * 1024 {
            capped = capped.min(1);
        } else if bytes_per_mask >= 24 * 1024 * 1024 {
            capped = capped.min(3);
        } else if bytes_per_mask >= 12 * 1024 * 1024 {
            capped = capped.min(6);
        }
    }

    capped.max(1)
}

fn choose_ctb_encode_queue_depth(worker_count: usize, expected_pixels: usize) -> usize {
    let bytes_per_mask = expected_pixels;
    if let Some(budget_bytes) = std::env::var("DF_V3_MAX_CTB_INFLIGHT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= 64)
        .map(|mb| mb.saturating_mul(1024 * 1024))
    {
        let allowed = (budget_bytes / bytes_per_mask.max(1)).max(1);
        return allowed.min((worker_count.saturating_mul(2)).max(1));
    }

    if bytes_per_mask >= 48 * 1024 * 1024 {
        1
    } else if bytes_per_mask >= 24 * 1024 * 1024 {
        2
    } else if bytes_per_mask >= 12 * 1024 * 1024 {
        3
    } else {
        (worker_count.saturating_mul(3)).clamp(3, 24)
    }
}

struct CtbRawMaskStreamingEncoder {
    job: SliceJobV3,
    work_tx: Option<mpsc::SyncSender<(u32, Vec<u8>)>>,
    result_rx: mpsc::Receiver<Result<ctb_types::CtbPreparedLayer, SlicerV3Error>>,
    workers: Vec<thread::JoinHandle<()>>,
    consumed_layers: u32,
}

impl RawMaskStreamEncoder for CtbRawMaskStreamingEncoder {
    fn consume_raw_mask_layer(
        &mut self,
        layer_index: u32,
        raw_mask: Vec<u8>,
    ) -> Result<(), SlicerV3Error> {
        let Some(ref tx) = self.work_tx else {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "CTB streaming encoder no longer accepts layers after finalize".to_string(),
            ));
        };

        tx.send((layer_index, raw_mask)).map_err(|_| {
            SlicerV3Error::MissingRenderedLayerPayload(
                "CTB streaming worker channel closed unexpectedly".to_string(),
            )
        })?;
        self.consumed_layers = self.consumed_layers.saturating_add(1);
        Ok(())
    }

    fn finalize_to_bytes(mut self: Box<Self>) -> Result<Vec<u8>, SlicerV3Error> {
        if self.consumed_layers == 0 {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "no rendered layers were provided for CTB encoding".to_string(),
            ));
        }

        // Close producer channel and let workers drain outstanding tasks.
        let _ = self.work_tx.take();

        while let Some(handle) = self.workers.pop() {
            if handle.join().is_err() {
                return Err(SlicerV3Error::UnsupportedOutput(
                    "CTB streaming worker panicked".to_string(),
                ));
            }
        }

        let expected_layers = self.consumed_layers as usize;
        let mut ordered: Vec<Option<ctb_types::CtbPreparedLayer>> =
            Vec::with_capacity(expected_layers);
        ordered.resize_with(expected_layers, || None);

        for _ in 0..expected_layers {
            let msg = self.result_rx.recv().map_err(|_| {
                SlicerV3Error::MissingRenderedLayerPayload(
                    "CTB streaming worker results ended unexpectedly".to_string(),
                )
            })?;

            let prepared = msg?;
            if prepared.index >= expected_layers {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB worker emitted out-of-range layer index {} (expected < {})",
                    prepared.index, expected_layers
                )));
            }
            let index = prepared.index;
            if ordered[index].is_some() {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB worker emitted duplicate layer index {}",
                    index
                )));
            }
            ordered[index] = Some(prepared);
        }

        let mut prepared = Vec::with_capacity(expected_layers);
        for (index, layer) in ordered.into_iter().enumerate() {
            let Some(layer) = layer else {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB layer {} missing from streaming worker output",
                    index
                )));
            };
            prepared.push(layer);
        }

        build_ctb_container_bytes(&self.job, &prepared)
    }
}

pub fn create_plugin_encoder() -> Vec<Box<dyn FormatEncoder>> {
    vec![Box::new(CtbPluginEncoder)]
}

// Parsing and layout logic live in `ctb_metadata.rs` and `ctb_layout.rs`.

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

    fn create_raw_mask_stream_encoder(
        &self,
        job: &SliceJobV3,
    ) -> Result<Option<Box<dyn RawMaskStreamEncoder>>, SlicerV3Error> {
        let threshold = parse_threshold_from_metadata(&job.metadata_json);
        let build = parse_ctb_build_model_from_job(job);
        let expected_pixels =
            (job.source_width_px as usize).saturating_mul(job.source_height_px as usize);

        let worker_count =
            cap_ctb_encode_workers_for_mask_bytes(choose_ctb_encode_threads(), expected_pixels);
        let queue_depth = choose_ctb_encode_queue_depth(worker_count, expected_pixels);
        let (work_tx, work_rx) = mpsc::sync_channel::<(u32, Vec<u8>)>(queue_depth);
        let (result_tx, result_rx) =
            mpsc::channel::<Result<ctb_types::CtbPreparedLayer, SlicerV3Error>>();
        let work_rx = Arc::new(Mutex::new(work_rx));
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();
            let worker_threshold = threshold;
            let worker_layer_xor_key = build.layer_xor_key;
            let worker_expected_pixels = expected_pixels;

            let handle = thread::spawn(move || loop {
                let task = match work_rx.lock() {
                    Ok(rx) => rx.recv(),
                    Err(_) => {
                        let _ = result_tx.send(Err(SlicerV3Error::UnsupportedOutput(
                            "CTB streaming work queue lock poisoned".to_string(),
                        )));
                        break;
                    }
                };

                let Ok((layer_index, raw_mask)) = task else {
                    break;
                };

                if raw_mask.is_empty() {
                    let prepared = encode_single_ctb_empty_layer(
                        layer_index as usize,
                        worker_expected_pixels,
                        worker_layer_xor_key,
                    );
                    crate::pipeline::return_mask_to_pool(raw_mask);

                    if result_tx.send(Ok(prepared)).is_err() {
                        break;
                    }
                    continue;
                }

                if raw_mask.len() != worker_expected_pixels {
                    let len = raw_mask.len();
                    crate::pipeline::return_mask_to_pool(raw_mask);
                    let _ =
                        result_tx.send(Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                            "CTB layer {layer_index} size mismatch: expected {} bytes, got {}",
                            worker_expected_pixels, len
                        ))));
                    continue;
                }

                let prepared = encode_single_ctb_layer_from_raw_mask(
                    layer_index as usize,
                    &raw_mask,
                    worker_threshold,
                    worker_layer_xor_key,
                );
                crate::pipeline::return_mask_to_pool(raw_mask);

                if result_tx.send(Ok(prepared)).is_err() {
                    break;
                }
            });

            workers.push(handle);
        }
        drop(result_tx);

        Ok(Some(Box::new(CtbRawMaskStreamingEncoder {
            job: job.clone(),
            work_tx: Some(work_tx),
            result_rx,
            workers,
            consumed_layers: 0,
        })))
    }

    fn estimate_encode_progress_units(&self, rendered_layers: &RenderedLayersV3) -> u32 {
        let layers = rendered_layers
            .raw_mask_layers
            .as_ref()
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        layers.saturating_mul(2).saturating_add(1).max(1)
    }

    fn encode_container_from_rendered_layers_with_progress(
        &self,
        job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        _layer_area_stats: &[LayerAreaStatsV3],
        on_progress: Option<&dyn Fn(u32, u32)>,
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

        let expected_pixels =
            (job.source_width_px as usize).saturating_mul(job.source_height_px as usize);
        for (idx, layer) in raw_masks.iter().enumerate() {
            if layer.len() != expected_pixels {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB layer {idx} size mismatch: expected {expected_pixels} bytes, got {}",
                    layer.len()
                )));
            }
        }

        let threshold = parse_threshold_from_metadata(&job.metadata_json);
        let build = parse_ctb_build_model_from_job(job);

        let total_prepare = raw_masks.len() as u32;
        let total_layout = raw_masks.len() as u32;
        let total_progress = total_prepare
            .saturating_add(total_layout)
            .saturating_add(1)
            .max(1);

        let prepare_progress = on_progress.map(|progress| {
            move |done: u32, total: u32| {
                let safe_total = total.max(1);
                let mapped = ((done.min(safe_total) as u64) * (total_prepare as u64)
                    / (safe_total as u64)) as u32;
                progress(mapped, total_progress);
            }
        });

        let prepared = prepare_layers_for_ctb_with_progress(
            raw_masks,
            threshold,
            build.layer_xor_key,
            prepare_progress.as_ref().map(|cb| cb as &dyn Fn(u32, u32)),
        );

        let source_bytes: usize = prepared.iter().map(|l| l.source_len).sum();
        let encoded_bytes: usize = prepared.iter().map(|l| l.encoded.len()).sum();
        if encoded_bytes == 0 {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB encoding produced empty payload (source bytes: {source_bytes})"
            )));
        }

        let layout_progress = on_progress.map(|progress| {
            move |done: u32, total: u32| {
                let safe_total = total.max(1);
                let mapped = ((done.min(safe_total) as u64) * (total_layout as u64)
                    / (safe_total as u64)) as u32;
                progress(total_prepare.saturating_add(mapped), total_progress);
            }
        });

        let bytes = build_ctb_container_bytes_with_progress(
            job,
            &prepared,
            layout_progress.as_ref().map(|cb| cb as &dyn Fn(u32, u32)),
        )?;

        if let Some(progress) = on_progress {
            progress(total_progress, total_progress);
        }

        Ok(bytes)
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

        let expected_pixels =
            (job.source_width_px as usize).saturating_mul(job.source_height_px as usize);
        for (idx, layer) in raw_masks.iter().enumerate() {
            if layer.len() != expected_pixels {
                return Err(SlicerV3Error::MissingRenderedLayerPayload(format!(
                    "CTB layer {idx} size mismatch: expected {expected_pixels} bytes, got {}",
                    layer.len()
                )));
            }
        }

        let threshold = parse_threshold_from_metadata(&job.metadata_json);
        let build = parse_ctb_build_model_from_job(job);
        let prepared = prepare_layers_for_ctb(raw_masks, threshold, build.layer_xor_key);

        let source_bytes: usize = prepared.iter().map(|l| l.source_len).sum();
        let encoded_bytes: usize = prepared.iter().map(|l| l.encoded.len()).sum();
        if encoded_bytes == 0 {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB encoding produced empty payload (source bytes: {source_bytes})"
            )));
        }

        build_ctb_container_bytes(job, &prepared)
    }

    fn encode_container_to_path(
        &self,
        job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        layer_area_stats: &[LayerAreaStatsV3],
        output_path: &Path,
    ) -> Result<(), SlicerV3Error> {
        let bytes =
            self.encode_container_from_rendered_layers(job, rendered_layers, layer_area_stats)?;
        std::fs::write(output_path, bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_ctb_container_bytes, ctb_layer_rle_xor, ctb_preview,
        decode_embedded_disclaimer_bytes, normalize_to_binary_mask, parse_threshold_from_metadata,
        push_ctb_run, rle_encode_mask_row_major, CtbPreparedLayer, CTB_DISCLAIMER_SIZE,
        CTB_HEADER_SIZE,
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
        let encoded = rle_encode_mask_row_major(&[0, 0, 255, 255, 255, 0]);
        assert_eq!(encoded, vec![0x80, 0x02, 0xff, 0x03, 0x00]);
    }

    #[test]
    fn rle_handles_long_runs_above_u8() {
        let input = vec![255u8; 300];
        let encoded = rle_encode_mask_row_major(&input);
        assert_eq!(encoded, vec![0xff, 0x81, 0x2c]);
    }

    #[test]
    fn ctb_run_encoder_supports_4byte_span_prefix() {
        let mut out = Vec::new();
        push_ctb_run(&mut out, 0x2A_BC_DE_u32, 255);

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
    fn layer_xor_roundtrip_restores_original() {
        let seed = 0x1234_5678;
        let layer_index = 7;
        let original = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 255];

        let mut encrypted = original.clone();
        ctb_layer_rle_xor(seed, layer_index, &mut encrypted);
        assert_ne!(encrypted, original);

        ctb_layer_rle_xor(seed, layer_index, &mut encrypted);
        assert_eq!(encrypted, original);
    }

    #[test]
    fn preview_rle_encodes_non_empty() {
        let rgb = vec![255u8, 0, 0, 255, 0, 0, 0, 0, 255];
        let rle = ctb_preview::encode_preview_rgb15_rle(&rgb);
        assert!(!rle.is_empty());
    }

    #[test]
    fn data_url_or_plain_base64_decode_works() {
        let tiny_png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlH0wAAAABJRU5ErkJggg==";
        let data_url = format!("data:image/png;base64,{tiny_png}");

        let a =
            ctb_preview::decode_base64_data_url_or_plain(tiny_png).expect("plain should decode");
        let b = ctb_preview::decode_base64_data_url_or_plain(&data_url)
            .expect("data-url should decode");
        assert_eq!(a, b);
    }

    #[test]
    fn embedded_disclaimer_decodes_without_plaintext_constant() {
        let bytes = decode_embedded_disclaimer_bytes().expect("embedded disclaimer should decode");
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= CTB_DISCLAIMER_SIZE);
    }

    #[test]
    fn ctb_container_writes_magic_and_header_fields() {
        let mut job = make_test_job();
        job.metadata_json = r#"{ "ctb": { "version": 4 } }"#.to_string();
        let prepared = vec![
            CtbPreparedLayer {
                index: 0,
                source_len: 16,
                encoded: vec![2, 0, 255],
            },
            CtbPreparedLayer {
                index: 1,
                source_len: 16,
                encoded: vec![1, 0, 0],
            },
        ];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("container should build");
        assert!(bytes.len() > CTB_HEADER_SIZE as usize);

        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let width = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let height = u32::from_le_bytes(bytes[56..60].try_into().unwrap());
        let layers = u32::from_le_bytes(bytes[68..72].try_into().unwrap());

        assert_eq!(magic, 0x12FD_0106);
        assert_eq!(version, 4);
        assert_eq!(width, 4);
        assert_eq!(height, 4);
        assert_eq!(layers, 2);
    }

    #[test]
    fn ctb_container_transfers_machine_name_bedsizez_and_modified_date() {
        let mut job = make_test_job();
        job.metadata_json = r#"{
            "ctb": {
                "version": 4,
                "MachineName": "DF Mega Printer",
                "ModifiedDate": 1735689600
            },
            "printer": {
                "buildVolumeMm": {
                    "width": 10,
                    "depth": 20,
                    "height": 180
                }
            }
        }"#
        .to_string();

        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("container should build");

        let bed_size_z = f32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let modified_date = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        assert!((bed_size_z - 180.0).abs() < 0.001);
        assert_eq!(modified_date, 1_735_689_600);

        let slicer_offset = u32::from_le_bytes(bytes[104..108].try_into().unwrap()) as usize;
        let machine_name_offset = u32::from_le_bytes(
            bytes[slicer_offset + 28..slicer_offset + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let machine_name_size = u32::from_le_bytes(
            bytes[slicer_offset + 32..slicer_offset + 36]
                .try_into()
                .unwrap(),
        ) as usize;
        let machine_name = String::from_utf8_lossy(
            &bytes[machine_name_offset..machine_name_offset.saturating_add(machine_name_size)],
        );
        assert_eq!(machine_name, "DF Mega Printer");
    }

    #[test]
    fn ctb_container_embeds_preview_offsets() {
        let job = make_test_job();
        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("container should build");
        let large_preview_offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap());
        let small_preview_offset = u32::from_le_bytes(bytes[72..76].try_into().unwrap());

        assert!(large_preview_offset >= CTB_HEADER_SIZE);
        assert!(small_preview_offset > large_preview_offset);
    }

    #[test]
    fn ctb_v4_writes_disclaimer_and_print_params_v4() {
        let mut job = make_test_job();
        job.metadata_json = r#"{ "ctb": { "version": 4 } }"#.to_string();
        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("container should build");

        let slicer_offset = u32::from_le_bytes(bytes[104..108].try_into().unwrap()) as usize;
        let print_params_v4_addr = u32::from_le_bytes(
            bytes[slicer_offset + 64..slicer_offset + 68]
                .try_into()
                .unwrap(),
        ) as usize;
        assert!(print_params_v4_addr > slicer_offset);

        let disclaimer_addr = u32::from_le_bytes(
            bytes[print_params_v4_addr + 72..print_params_v4_addr + 76]
                .try_into()
                .unwrap(),
        ) as usize;
        let disclaimer_len = u32::from_le_bytes(
            bytes[print_params_v4_addr + 76..print_params_v4_addr + 80]
                .try_into()
                .unwrap(),
        ) as usize;

        assert_eq!(disclaimer_len, CTB_DISCLAIMER_SIZE);
        assert!(disclaimer_addr + disclaimer_len <= bytes.len());
    }

    #[test]
    fn ctb_v5_writes_resin_parameters_address() {
        let mut job = make_test_job();
        job.metadata_json =
            r#"{ "ctb": { "version": 5, "resinName": "FastResin", "resinType": "ABS-Like" } }"#
                .to_string();

        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("container should build");

        let slicer_offset = u32::from_le_bytes(bytes[104..108].try_into().unwrap()) as usize;
        let print_params_v4_addr = u32::from_le_bytes(
            bytes[slicer_offset + 64..slicer_offset + 68]
                .try_into()
                .unwrap(),
        ) as usize;
        let resin_addr = u32::from_le_bytes(
            bytes[print_params_v4_addr + 80..print_params_v4_addr + 84]
                .try_into()
                .unwrap(),
        ) as usize;

        assert!(resin_addr > print_params_v4_addr);
        assert!(resin_addr < bytes.len());
    }

    #[test]
    fn ctb_aes_mode_writes_encrypted_magic_and_signature_trailer() {
        let mut job = make_test_job();
        job.metadata_json = r#"{
            "ctb": {
                "version": 5,
                "aes": {
                    "enabled": true
                }
            }
        }"#
        .to_string();

        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let bytes = build_ctb_container_bytes(&job, &prepared).expect("aes mode should build");

        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, 0x12FD_0107);

        assert!(bytes.len() > 12);
        let tail = &bytes[bytes.len() - 4..];
        let trailer = u32::from_le_bytes(tail.try_into().unwrap());
        assert_eq!(trailer, 0x6D42_32B3);

        let marker_pos = bytes
            .windows(4)
            .position(|w| w == 0x4220_52FAu32.to_le_bytes())
            .expect("signature marker should exist");
        assert!(marker_pos > CTB_HEADER_SIZE as usize);
    }

    #[test]
    fn ctb_aes_mode_rejects_invalid_key_or_iv_lengths() {
        let mut job = make_test_job();
        job.metadata_json = r#"{
            "ctb": {
                "version": 5,
                "aes": {
                    "enabled": true,
                    "keyBase64": "MDEyMzQ1Njc4OWFiY2RlZg==",
                    "ivBase64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ=="
                }
            }
        }"#
        .to_string();

        let prepared = vec![CtbPreparedLayer {
            index: 0,
            source_len: 16,
            encoded: vec![2, 0, 255],
        }];

        let err = build_ctb_container_bytes(&job, &prepared)
            .expect_err("invalid key/iv lengths should be rejected");
        assert!(err.to_string().contains("CTB AES key must be 32 bytes"));
    }
}
