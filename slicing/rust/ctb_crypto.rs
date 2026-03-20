use crate::engine::SlicerV3Error;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use aes::Aes256;

const CTB_AES_OBFUSCATION: &[u8; 14] = b"DragonFruitFTW";
const CTB_AES_DEFAULT_KEY_XOR: [u8; 32] = [
    0x94, 0x29, 0xEF, 0x54, 0x1E, 0xB0, 0x7B, 0x68, 0x90, 0x26, 0x56, 0x9B, 0x8B, 0x0C, 0xB9, 0xE6,
    0xCA, 0x3A, 0x0B, 0x54, 0xDB, 0x0C, 0xCA, 0xC6, 0x36, 0x45, 0xA7, 0x47, 0x9C, 0x20, 0x4B, 0x8D,
];
const CTB_AES_DEFAULT_IV_XOR: [u8; 16] = [
    0x4B, 0x73, 0x6B, 0x62, 0x6A, 0x65, 0x40, 0x75, 0x7D, 0x6F, 0x7E, 0x4A, 0x58, 0x5A, 0x4D, 0x7D,
];

fn xor_deobfuscate<const N: usize>(input: [u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0usize;
    while i < N {
        out[i] = input[i] ^ CTB_AES_OBFUSCATION[i % CTB_AES_OBFUSCATION.len()];
        i += 1;
    }
    out
}

pub(super) fn ctb_default_key_iv() -> ([u8; 32], [u8; 16]) {
    (
        xor_deobfuscate(CTB_AES_DEFAULT_KEY_XOR),
        xor_deobfuscate(CTB_AES_DEFAULT_IV_XOR),
    )
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
