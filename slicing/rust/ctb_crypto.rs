use crate::engine::SlicerV3Error;
use aes::cipher::block_padding::{NoPadding, ZeroPadding};
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use aes::Aes256;

use super::ctb_types::CtbAesModel;

const CTB_AES_DEFAULT_KEY: [u8; 32] = [
    0xD0, 0x5B, 0x8E, 0x33, 0x71, 0xDE, 0x3D, 0x1A, 0xE5, 0x4F, 0x22, 0xDD, 0xDF, 0x5B, 0xFD, 0x94,
    0xAB, 0x5D, 0x64, 0x3A, 0x9D, 0x7E, 0xBF, 0xAF, 0x42, 0x03, 0xF3, 0x10, 0xD8, 0x52, 0x2A, 0xEA,
];
const CTB_AES_DEFAULT_IV: [u8; 16] = [
    0x0F, 0x01, 0x0A, 0x05, 0x05, 0x0B, 0x06, 0x07, 0x08, 0x06, 0x0A, 0x0C, 0x0C, 0x0D, 0x09, 0x0F,
];

pub(super) fn resolve_ctb_aes_material(
    aes: &CtbAesModel,
) -> Result<Option<([u8; 32], [u8; 16])>, SlicerV3Error> {
    if !aes.enabled {
        return Ok(None);
    }

    let mut key = CTB_AES_DEFAULT_KEY;
    if let Some(k) = aes.key.as_ref() {
        if k.len() != 32 {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES key must be 32 bytes when provided, got {} bytes",
                k.len()
            )));
        }
        key.copy_from_slice(k);
    }

    let mut iv = CTB_AES_DEFAULT_IV;
    if let Some(v) = aes.iv.as_ref() {
        if v.len() != 16 {
            return Err(SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES IV must be 16 bytes when provided, got {} bytes",
                v.len()
            )));
        }
        iv.copy_from_slice(v);
    }

    Ok(Some((key, iv)))
}

pub(super) fn ctb_encrypt_in_place_no_padding(
    bytes: &mut [u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<(), SlicerV3Error> {
    if bytes.is_empty() {
        return Ok(());
    }

    if bytes.len() % 16 != 0 {
        return Err(SlicerV3Error::UnsupportedOutput(format!(
            "CTB AES no-padding block must be multiple of 16 bytes, got {} bytes",
            bytes.len()
        )));
    }

    let len = bytes.len();
    cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(bytes, len)
        .map_err(|e| {
            SlicerV3Error::UnsupportedOutput(format!(
                "CTB AES encryption failed for fixed-size block: {e}"
            ))
        })?;

    Ok(())
}

pub(super) fn ctb_encrypt_padded_vec(
    bytes: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, SlicerV3Error> {
    let mut out = bytes.to_vec();
    out.resize(out.len().next_multiple_of(32), 0);
    let len = out.len();

    cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
        .encrypt_padded_mut::<ZeroPadding>(&mut out, len)
        .map_err(|e| SlicerV3Error::UnsupportedOutput(format!("CTB AES encryption failed: {e}")))?;

    Ok(out)
}

pub(super) fn pad_vec_to_block(bytes: &mut Vec<u8>, block: usize) {
    if block == 0 {
        return;
    }
    let rem = bytes.len() % block;
    if rem == 0 {
        return;
    }
    bytes.resize(bytes.len() + (block - rem), 0);
}
