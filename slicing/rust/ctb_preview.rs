use crate::engine::SlicerV3Error;
use crate::types::SliceJobV3;
use base64::Engine;
use std::io::Cursor;

use super::ctb_types::{
    CtbPreviewBlob, PREVIEW_LARGE_H, PREVIEW_LARGE_W, PREVIEW_REPEAT_RGB15_MASK,
    PREVIEW_RLE16_ENCODING_LIMIT, PREVIEW_SMALL_H, PREVIEW_SMALL_W,
};

pub(super) fn decode_base64_data_url_or_plain(input: &str) -> Result<Vec<u8>, SlicerV3Error> {
    let payload = input
        .split_once(',')
        .map(|(_, rhs)| rhs)
        .unwrap_or(input)
        .trim();

    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|e| SlicerV3Error::Png(format!("invalid base64 preview payload: {e}")))
}

fn decode_png_rgba8(png_bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), SlicerV3Error> {
    let cursor = Cursor::new(png_bytes);
    let mut decoder = png::Decoder::new(cursor);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);

    let mut reader = decoder
        .read_info()
        .map_err(|e| SlicerV3Error::Png(format!("png decode header failed: {e}")))?;

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| SlicerV3Error::Png(format!("png decode frame failed: {e}")))?;

    let src = &buf[..info.buffer_size()];
    let mut out = Vec::with_capacity((info.width as usize) * (info.height as usize) * 4);

    match info.color_type {
        png::ColorType::Rgb => {
            for px in src.chunks_exact(3) {
                out.push(px[0]);
                out.push(px[1]);
                out.push(px[2]);
                out.push(255);
            }
        }
        png::ColorType::Rgba => {
            out.extend_from_slice(src);
        }
        png::ColorType::Grayscale => {
            for &g in src {
                out.push(g);
                out.push(g);
                out.push(g);
                out.push(255);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for px in src.chunks_exact(2) {
                let g = px[0];
                out.push(g);
                out.push(g);
                out.push(g);
                out.push(px[1]);
            }
        }
        png::ColorType::Indexed => {
            return Err(SlicerV3Error::Png(
                "indexed PNG preview is not supported after decode transforms".to_string(),
            ));
        }
    }

    Ok((info.width, info.height, out))
}

fn resize_and_blend_rgba_to_rgb_nearest(
    src_w: u32,
    src_h: u32,
    src_rgba: &[u8],
    dst_w: u32,
    dst_h: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; (dst_w as usize) * (dst_h as usize) * 3];

    let src_w_nz = src_w.max(1);
    let src_h_nz = src_h.max(1);
    let dst_w_nz = dst_w.max(1);
    let dst_h_nz = dst_h.max(1);

    let src_ratio_left = src_w_nz as u64 * dst_h_nz as u64;
    let dst_ratio_right = dst_w_nz as u64 * src_h_nz as u64;

    let (inner_w, inner_h) = if src_ratio_left > dst_ratio_right {
        let h = ((dst_w_nz as u64) * (src_h_nz as u64) / (src_w_nz as u64)) as u32;
        (dst_w_nz, h.max(1))
    } else {
        let w = ((dst_h_nz as u64) * (src_w_nz as u64) / (src_h_nz as u64)) as u32;
        (w.max(1), dst_h_nz)
    };

    let offset_x = dst_w_nz.saturating_sub(inner_w) / 2;
    let offset_y = dst_h_nz.saturating_sub(inner_h) / 2;

    let gradient_start = [32u32, 10u32, 42u32]; // dark dragonfruit purple
    let gradient_end = [14u32, 34u32, 14u32]; // dark dragonfruit green

    for y in 0..dst_h {
        let mut out_idx = ((y as usize) * (dst_w as usize)) * 3;
        for x in 0..dst_w {
            let denom = (dst_w_nz as u64 + dst_h_nz as u64).max(1);
            let t = ((x as u64 + y as u64) * 255 / denom) as u32;
            let bg_r = ((gradient_start[0] * (255 - t) + gradient_end[0] * t) / 255) as u32;
            let bg_g = ((gradient_start[1] * (255 - t) + gradient_end[1] * t) / 255) as u32;
            let bg_b = ((gradient_start[2] * (255 - t) + gradient_end[2] * t) / 255) as u32;

            if x >= offset_x && x < offset_x + inner_w && y >= offset_y && y < offset_y + inner_h {
                let local_x = x - offset_x;
                let local_y = y - offset_y;

                let sx = ((local_x as u64) * (src_w_nz as u64) / (inner_w as u64)) as u32;
                let sy = ((local_y as u64) * (src_h_nz as u64) / (inner_h as u64)) as u32;

                let sx = sx.min(src_w.saturating_sub(1));
                let sy = sy.min(src_h.saturating_sub(1));

                let src_idx = ((sy as usize) * (src_w as usize) + (sx as usize)) * 4;
                let r = src_rgba[src_idx] as u32;
                let g = src_rgba[src_idx + 1] as u32;
                let b = src_rgba[src_idx + 2] as u32;
                let a = src_rgba[src_idx + 3] as u32;

                if a == 255 {
                    out[out_idx] = r as u8;
                    out[out_idx + 1] = g as u8;
                    out[out_idx + 2] = b as u8;
                } else if a == 0 {
                    out[out_idx] = bg_r as u8;
                    out[out_idx + 1] = bg_g as u8;
                    out[out_idx + 2] = bg_b as u8;
                } else {
                    let inv_a = 255 - a;
                    out[out_idx] = ((r * a + bg_r * inv_a) / 255) as u8;
                    out[out_idx + 1] = ((g * a + bg_g * inv_a) / 255) as u8;
                    out[out_idx + 2] = ((b * a + bg_b * inv_a) / 255) as u8;
                }
            } else {
                out[out_idx] = bg_r as u8;
                out[out_idx + 1] = bg_g as u8;
                out[out_idx + 2] = bg_b as u8;
            }
            out_idx += 3;
        }
    }

    out
}

fn rgb888_to_rgb15_word(r: u8, g: u8, b: u8) -> u16 {
    ((r as u16 >> 3) << 11) | ((g as u16 >> 3) << 6) | (b as u16 >> 3)
}

fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.push((v & 0xff) as u8);
    out.push((v >> 8) as u8);
}

pub(super) fn encode_preview_rgb15_rle(rgb: &[u8]) -> Vec<u8> {
    if rgb.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(rgb.len() / 2);

    let mut i = 0usize;
    let mut current = rgb888_to_rgb15_word(rgb[0], rgb[1], rgb[2]);
    let mut run: u32 = 1;
    i += 3;

    let flush = |buf: &mut Vec<u8>, color: u16, rep: u32| {
        if rep == 0 {
            return;
        }

        if rep == 1 {
            push_u16_le(buf, color & !PREVIEW_REPEAT_RGB15_MASK);
            return;
        }

        if rep == 2 {
            let word = color & !PREVIEW_REPEAT_RGB15_MASK;
            push_u16_le(buf, word);
            push_u16_le(buf, word);
            return;
        }

        let repeat_word = color | PREVIEW_REPEAT_RGB15_MASK;
        push_u16_le(buf, repeat_word);

        let rep_minus_1 = (rep - 1).min(PREVIEW_RLE16_ENCODING_LIMIT) as u16;
        let count_word = 0x3000 | (rep_minus_1 & 0x0fff);
        push_u16_le(buf, count_word);
    };

    while i + 2 < rgb.len() {
        let next = rgb888_to_rgb15_word(rgb[i], rgb[i + 1], rgb[i + 2]);
        i += 3;

        if next == current && run < PREVIEW_RLE16_ENCODING_LIMIT + 1 {
            run += 1;
            continue;
        }

        flush(&mut out, current, run);
        current = next;
        run = 1;
    }

    flush(&mut out, current, run);
    out
}

pub(super) fn build_previews(job: &SliceJobV3) -> Result<[CtbPreviewBlob; 2], SlicerV3Error> {
    let source_rgb = if let Some(base64_png) = job.export_thumbnail_png_base64.as_ref() {
        let png_bytes = decode_base64_data_url_or_plain(base64_png)?;
        let (w, h, rgb) = decode_png_rgba8(&png_bytes)?;
        Some((w, h, rgb))
    } else {
        None
    };

    let build_one = |dst_w: u32, dst_h: u32| -> CtbPreviewBlob {
        let rgb = if let Some((src_w, src_h, src_rgb)) = source_rgb.as_ref() {
            resize_and_blend_rgba_to_rgb_nearest(*src_w, *src_h, src_rgb, dst_w, dst_h)
        } else {
            // Give it a 1x1 transparent pixel so it just draws the gradient background
            resize_and_blend_rgba_to_rgb_nearest(1, 1, &[0, 0, 0, 0], dst_w, dst_h)
        };

        CtbPreviewBlob {
            width: dst_w,
            height: dst_h,
            encoded: encode_preview_rgb15_rle(&rgb),
        }
    };

    Ok([
        build_one(PREVIEW_LARGE_W, PREVIEW_LARGE_H),
        build_one(PREVIEW_SMALL_W, PREVIEW_SMALL_H),
    ])
}

pub(super) fn write_preview_record(
    out: &mut Vec<u8>,
    width: u32,
    height: u32,
    image_offset: u32,
    image_length: u32,
) {
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&image_offset.to_le_bytes());
    out.extend_from_slice(&image_length.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
}
