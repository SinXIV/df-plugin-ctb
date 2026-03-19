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

fn decode_png_rgb8(png_bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), SlicerV3Error> {
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
    let mut out = Vec::with_capacity((info.width as usize) * (info.height as usize) * 3);

    match info.color_type {
        png::ColorType::Rgb => {
            out.extend_from_slice(src);
        }
        png::ColorType::Rgba => {
            for px in src.chunks_exact(4) {
                out.push(px[0]);
                out.push(px[1]);
                out.push(px[2]);
            }
        }
        png::ColorType::Grayscale => {
            for &g in src {
                out.push(g);
                out.push(g);
                out.push(g);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            for px in src.chunks_exact(2) {
                let g = px[0];
                out.push(g);
                out.push(g);
                out.push(g);
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

fn resize_rgb_nearest(src_w: u32, src_h: u32, src_rgb: &[u8], dst_w: u32, dst_h: u32) -> Vec<u8> {
    if src_w == dst_w && src_h == dst_h {
        return src_rgb.to_vec();
    }

    let mut out = vec![0u8; (dst_w as usize) * (dst_h as usize) * 3];

    for y in 0..dst_h {
        let sy = ((y as u64) * (src_h as u64) / (dst_h as u64)) as u32;
        for x in 0..dst_w {
            let sx = ((x as u64) * (src_w as u64) / (dst_w as u64)) as u32;

            let s_idx = ((sy as usize) * (src_w as usize) + (sx as usize)) * 3;
            let d_idx = ((y as usize) * (dst_w as usize) + (x as usize)) * 3;

            out[d_idx..d_idx + 3].copy_from_slice(&src_rgb[s_idx..s_idx + 3]);
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
        let (w, h, rgb) = decode_png_rgb8(&png_bytes)?;
        Some((w, h, rgb))
    } else {
        None
    };

    let build_one = |dst_w: u32, dst_h: u32| -> CtbPreviewBlob {
        let rgb = if let Some((src_w, src_h, src_rgb)) = source_rgb.as_ref() {
            resize_rgb_nearest(*src_w, *src_h, src_rgb, dst_w, dst_h)
        } else {
            vec![0u8; (dst_w as usize) * (dst_h as usize) * 3]
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
