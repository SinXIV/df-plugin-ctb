use crate::encoders::FormatEncoder;
use crate::engine::SlicerV3Error;
use crate::types::{LayerAreaStatsV3, RenderedLayersV3, SliceJobV3};
use std::path::Path;

pub struct CtbPluginEncoder;

pub fn create_plugin_encoder() -> Vec<Box<dyn FormatEncoder>> {
    vec![Box::new(CtbPluginEncoder)]
}

fn rle_encode_mask_row_major(mask: &[u8]) -> Vec<u8> {
    if mask.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(mask.len() / 2);
    let mut run_value = mask[0];
    let mut run_len: u8 = 1;

    for &px in &mask[1..] {
        if px == run_value && run_len < u8::MAX {
            run_len = run_len.saturating_add(1);
            continue;
        }

        out.push(run_len);
        out.push(run_value);
        run_value = px;
        run_len = 1;
    }

    out.push(run_len);
    out.push(run_value);
    out
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
        _job: &SliceJobV3,
        rendered_layers: &RenderedLayersV3,
        _layer_area_stats: &[LayerAreaStatsV3],
    ) -> Result<Vec<u8>, SlicerV3Error> {
        let Some(raw_masks) = rendered_layers.raw_mask_layers.as_ref() else {
            return Err(SlicerV3Error::MissingRenderedLayerPayload(
                "raw mask layers are required for CTB encoding".to_string(),
            ));
        };

        // Phase 1 implementation: exercise and validate the raw-layer + RLE path.
        // Final CTB container serialization will be added in follow-up commits.
        let _rle_layers: Vec<Vec<u8>> = raw_masks
            .iter()
            .map(|layer| rle_encode_mask_row_major(layer))
            .collect();

        Err(SlicerV3Error::UnsupportedOutput(
            "CTB container serialization is not implemented yet".to_string(),
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
