//! VMK keyslot: wrapping, unwrapping and the Encrypt-then-MAC tag.
//!
//! Every encrypted bundle has one random 32-byte **volume master key (VMK)**
//! that the payload cipher actually uses. The VMK is never stored directly.
//! Instead the manifest carries one **keyslot**:
//!
//! ```text
//! credential (password / 32-byte key)
//!    │ PBKDF2-HMAC-SHA256(salt, iterations) / raw key
//!    ▼
//!   KEK (32 B)
//!    │ wrap_key = HMAC-SHA256(KEK, "snowscsi-wrap-v1" || salt || wrap_nonce)
//!    │ mac_key  = HMAC-SHA256(KEK, "snowscsi-mac-v1"  || salt || wrap_nonce)
//!    ├─ wrapped_key = VMK XOR ChaCha20(wrap_key, wrap_nonce)[0..32]
//!    └─ tag = HMAC-SHA256(mac_key, tag_input)[..16]
//! ```
//!
//! [`key_id`] is `HMAC-SHA256(VMK, "snowscsi-keyid-v1")[..8]`; it lets a caller
//! tell whether two manifests wrap the same VMK.
//!
//! # What the tag covers
//!
//! The tag binds the **keyslot and the bundle identity** (kind, geometry,
//! cipher, data nonce, key ID, KDF parameters and the wrapped key). It does
//! **not** authenticate the payload: the stream ciphers are malleable and a
//! modified image decrypts to wrong bytes instead of reporting tampering.
//! `tag_input` is fixed-width binary and independent of the manifest text
//! order.
//!
//! # Verify before unwrap
//!
//! [`unwrap_slot`] verifies the tag **before** decrypting the wrapped key, so
//! a wrong credential or a tampered keyslot/identity fails cleanly instead of
//! producing a wrong VMK. The failure is always
//! [`KeyslotError::WrongPasswordOrCorruptKeyslot`]; it deliberately does not
//! reveal which check failed.
//!
//! # No zeroize
//!
//! Key material is not scrubbed. [`CipherKey`] and intermediate subkeys stay
//! in ordinary RAM for their whole lifetime and there is no `zeroize`
//! dependency; callers that need scrubbing must supply it.
//!
//! # Rekeying
//!
//! A rekey changes only the keyslot (salt, iterations, wrap nonce, wrapped key
//! and tag) for the **same** VMK. It never changes the data nonce, cipher,
//! kind, geometry or size, so the payload is not re-encrypted.

use super::chacha::ChaCha20;
use super::kdf::{hmac_sha256, Kdf, SoftKdf};
use super::{CipherKey, StreamCipher};
use crate::bundle::{BundleKind, CipherAlg, CipherMeta, KdfKind, KeySlot, VERSION};

/// Keyslot / credential failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyslotError {
    /// A PBKDF2 keyslot needs a password.
    MissingPassword,
    /// A `kdf = none` keyslot needs a 32-byte key.
    MissingKeyFile,
    /// The credential is wrong, or the keyslot/identity was tampered with.
    WrongPasswordOrCorruptKeyslot,
    /// An internal cryptographic step failed (invalid parameters).
    Crypto,
}

impl core::fmt::Display for KeyslotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingPassword => write!(f, "password required for this keyslot"),
            Self::MissingKeyFile => write!(f, "key file required for this keyslot"),
            Self::WrongPasswordOrCorruptKeyslot => {
                write!(f, "wrong password/key or corrupt keyslot")
            }
            Self::Crypto => write!(f, "keyslot cryptography failed"),
        }
    }
}

impl core::error::Error for KeyslotError {}

/// `HMAC-SHA256(vmk, "snowscsi-keyid-v1")[..8]`.
pub fn key_id(vmk: &CipherKey) -> [u8; 8] {
    let digest = hmac_sha256(vmk.as_bytes(), b"snowscsi-keyid-v1");
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Derive the KEK from the slot's credential.
///
/// `PBKDF2-HMAC-SHA256` requires `password` and uses the slot's iteration
/// count and salt; `kdf = none` requires a 32-byte `key` and returns it
/// unchanged. Reading and length-checking a key file is the caller's job.
pub fn derive_kek(
    slot: &KeySlot,
    password: Option<&[u8]>,
    key: Option<&CipherKey>,
) -> Result<CipherKey, KeyslotError> {
    match slot.kdf {
        KdfKind::Pbkdf2HmacSha256 => {
            let password = password.ok_or(KeyslotError::MissingPassword)?;
            let iterations = slot.iterations.ok_or(KeyslotError::Crypto)?;
            let mut kek = [0u8; 32];
            let mut kdf = SoftKdf;
            kdf.derive(password, &slot.salt, iterations, &mut kek)
                .map_err(|_| KeyslotError::Crypto)?;
            let out = CipherKey::from_bytes(&kek).map_err(|_| KeyslotError::Crypto)?;
            kek.fill(0);
            core::hint::black_box(&mut kek);
            Ok(out)
        }
        KdfKind::None => {
            let key = key.ok_or(KeyslotError::MissingKeyFile)?;
            CipherKey::from_bytes(key.as_bytes()).map_err(|_| KeyslotError::Crypto)
        }
    }
}

/// Wrap `vmk` into `meta.slot` using `kek`.
///
/// The caller must already have filled `meta.cipher`, `meta.nonce`,
/// `meta.key_id`, `meta.slot.kdf`, `meta.slot.iterations` and
/// `meta.slot.salt`/`wrap_nonce`. This function fills `wrapped_key` and `tag`.
pub fn wrap_slot(
    kind: &BundleKind,
    meta: &mut CipherMeta,
    kek: &CipherKey,
    vmk: &CipherKey,
) -> Result<(), KeyslotError> {
    let wrap_key = subkey(kek, b"snowscsi-wrap-v1", &meta.slot)?;
    let mac_key = subkey(kek, b"snowscsi-mac-v1", &meta.slot)?;

    let mut wrapped = [0u8; 32];
    wrapped.copy_from_slice(vmk.as_bytes());
    ChaCha20::new(&wrap_key, meta.slot.wrap_nonce)
        .map_err(|_| KeyslotError::Crypto)?
        .xor(0, &mut wrapped)
        .map_err(|_| KeyslotError::Crypto)?;
    meta.slot.wrapped_key = wrapped;

    let (input, len) = tag_input(kind, meta);
    let digest = hmac_sha256(mac_key.as_bytes(), &input[..len]);
    meta.slot.tag.copy_from_slice(&digest[..16]);
    Ok(())
}

/// Verify the keyslot tag and unwrap the VMK.
///
/// The tag is checked first; a mismatch (wrong credential, tampered keyslot or
/// changed identity) is [`KeyslotError::WrongPasswordOrCorruptKeyslot`].
pub fn unwrap_slot(
    kind: &BundleKind,
    meta: &CipherMeta,
    kek: &CipherKey,
) -> Result<CipherKey, KeyslotError> {
    let wrap_key = subkey(kek, b"snowscsi-wrap-v1", &meta.slot)?;
    let mac_key = subkey(kek, b"snowscsi-mac-v1", &meta.slot)?;

    let (input, len) = tag_input(kind, meta);
    let digest = hmac_sha256(mac_key.as_bytes(), &input[..len]);
    if !constant_time_eq(&digest[..16], &meta.slot.tag) {
        return Err(KeyslotError::WrongPasswordOrCorruptKeyslot);
    }

    let mut vmk = meta.slot.wrapped_key;
    ChaCha20::new(&wrap_key, meta.slot.wrap_nonce)
        .map_err(|_| KeyslotError::Crypto)?
        .xor(0, &mut vmk)
        .map_err(|_| KeyslotError::Crypto)?;
    let vmk = CipherKey::from_bytes(&vmk).map_err(|_| KeyslotError::Crypto)?;
    // The tag authenticates the keyslot, but the key id is the manifest's
    // explicit fingerprint of the VMK; check it too so a keyslot transplanted
    // with a forged tag/key_id cannot unlock a different VMK.
    if key_id(&vmk) != meta.key_id {
        return Err(KeyslotError::WrongPasswordOrCorruptKeyslot);
    }
    Ok(vmk)
}

/// `HMAC-SHA256(KEK, label || salt || wrap_nonce)`.
fn subkey(kek: &CipherKey, label: &[u8], slot: &KeySlot) -> Result<CipherKey, KeyslotError> {
    let mut data = [0u8; 40];
    let label_len = label.len();
    data[..label_len].copy_from_slice(label);
    data[label_len..label_len + 16].copy_from_slice(&slot.salt);
    data[label_len + 16..label_len + 24].copy_from_slice(&slot.wrap_nonce);
    let digest = hmac_sha256(kek.as_bytes(), &data[..label_len + 24]);
    CipherKey::from_bytes(&digest).map_err(|_| KeyslotError::Crypto)
}

/// Fixed-width binary tag input (independent of the manifest text order).
///
/// Layout: label (19), version u32 BE, kind u8, kind geometry, cipher u8,
/// data nonce [8], key id [8], kdf u8, iterations u32 BE, salt [16],
/// wrap nonce [8], wrapped key [32].
fn tag_input(kind: &BundleKind, meta: &CipherMeta) -> ([u8; 130], usize) {
    let mut out = [0u8; 130];
    let mut len = 0usize;

    let label = b"snowscsi-keyslot-v1";
    out[..label.len()].copy_from_slice(label);
    len += label.len();

    out[len..len + 4].copy_from_slice(&VERSION.to_be_bytes());
    len += 4;

    out[len] = kind_code(kind);
    len += 1;
    match kind {
        BundleKind::Image { size } => {
            out[len..len + 8].copy_from_slice(&size.to_be_bytes());
            len += 8;
        }
        BundleKind::Flat {
            virtual_size,
            chunk_size,
            sector_size,
        } => {
            out[len..len + 8].copy_from_slice(&virtual_size.to_be_bytes());
            len += 8;
            out[len..len + 8].copy_from_slice(&chunk_size.to_be_bytes());
            len += 8;
            out[len..len + 4].copy_from_slice(&sector_size.to_be_bytes());
            len += 4;
        }
        BundleKind::Cdr => {}
    }

    out[len] = cipher_code(meta.cipher);
    len += 1;
    out[len..len + 8].copy_from_slice(&meta.nonce);
    len += 8;
    out[len..len + 8].copy_from_slice(&meta.key_id);
    len += 8;

    out[len] = kdf_code(meta.slot.kdf);
    len += 1;
    let iterations = match meta.slot.kdf {
        KdfKind::Pbkdf2HmacSha256 => meta.slot.iterations.unwrap_or(0),
        KdfKind::None => 0,
    };
    out[len..len + 4].copy_from_slice(&iterations.to_be_bytes());
    len += 4;

    out[len..len + 16].copy_from_slice(&meta.slot.salt);
    len += 16;
    out[len..len + 8].copy_from_slice(&meta.slot.wrap_nonce);
    len += 8;
    out[len..len + 32].copy_from_slice(&meta.slot.wrapped_key);
    len += 32;

    (out, len)
}

const fn kind_code(kind: &BundleKind) -> u8 {
    match kind {
        BundleKind::Image { .. } => 0,
        BundleKind::Flat { .. } => 1,
        BundleKind::Cdr => 2,
    }
}

const fn cipher_code(cipher: CipherAlg) -> u8 {
    match cipher {
        CipherAlg::ChaCha8 => 0,
        CipherAlg::ChaCha12 => 1,
        CipherAlg::ChaCha20 => 2,
        CipherAlg::AesCtr => 3,
        CipherAlg::Xor => 4,
    }
}

const fn kdf_code(kdf: KdfKind) -> u8 {
    match kdf {
        KdfKind::Pbkdf2HmacSha256 => 0,
        KdfKind::None => 1,
    }
}

/// Compare two byte strings without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleKind, CipherAlg, CipherMeta, KdfKind, KeySlot};

    /// Unhex a compile-time-length hex literal without `alloc`.
    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        let bytes = hex.as_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *b = (hi << 4) | lo;
        }
        out
    }

    fn key(bytes: [u8; 32]) -> CipherKey {
        CipherKey::from_bytes(&bytes).unwrap()
    }

    // Key material shared by the vectors below (all constants are
    // independently computed with Python `hashlib`/`hmac` and an independent
    // DJB ChaCha20 implementation).
    const VMK: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const KEK_NONE: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    const SALT: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const WRAP_NONCE: [u8; 8] = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7];
    const DATA_NONCE: [u8; 8] = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    const KEY_ID: [u8; 8] = [0xa3, 0x26, 0x7f, 0x36, 0xcd, 0xed, 0xf5, 0x9f];
    const WRAPPED_NONE: [u8; 32] = [
        0xa5, 0xce, 0x4a, 0xc9, 0xff, 0xd1, 0x89, 0xd6, 0x35, 0x19, 0x3e, 0xae, 0x97, 0xd8, 0x4d,
        0xd9, 0xf0, 0xcf, 0xc9, 0x3f, 0xb7, 0x27, 0xa0, 0x8a, 0xac, 0x15, 0xec, 0xbb, 0x06, 0x94,
        0x6c, 0x9b,
    ];
    const TAG_NONE: [u8; 16] = [
        0x41, 0x61, 0xe8, 0xb4, 0xc8, 0x21, 0x85, 0xd1, 0xf0, 0xb0, 0x2a, 0xdd, 0xfe, 0xf9, 0xd2,
        0x40,
    ];
    const WRAPPED_NONE_ALT: [u8; 32] = [
        0xc9, 0x9c, 0x53, 0xe5, 0x80, 0xf0, 0xde, 0xb2, 0x74, 0x13, 0x76, 0xf1, 0x90, 0xb7, 0x32,
        0xdc, 0x75, 0x40, 0x3c, 0x9b, 0x84, 0xc0, 0x75, 0xad, 0xc0, 0xf7, 0x6a, 0x5e, 0x6d, 0x5b,
        0x43, 0x62,
    ];
    const TAG_NONE_ALT: [u8; 16] = [
        0x5c, 0x18, 0xac, 0x00, 0xe7, 0x80, 0x40, 0xb9, 0xca, 0x80, 0x47, 0xe1, 0x27, 0xfc, 0xe0,
        0x46,
    ];
    const PASSWORD: &[u8] = b"correct horse battery staple";
    const PASSWORD_SALT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    const PASSWORD_ITERATIONS: u32 = 1000;
    const KEK_PBKDF2: [u8; 32] = [
        0xdf, 0xb2, 0x33, 0xc3, 0xb5, 0x06, 0x55, 0x75, 0xef, 0x40, 0x43, 0x28, 0xc8, 0x81, 0xa0,
        0xcb, 0xa7, 0x1b, 0x71, 0x80, 0xf7, 0x22, 0x98, 0xa2, 0xed, 0xc5, 0xea, 0x5f, 0x3a, 0x4c,
        0x02, 0xf9,
    ];
    const PASSWORD_WRAP_NONCE: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const PASSWORD_DATA_NONCE: [u8; 8] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const PASSWORD_WRAPPED: [u8; 32] = [
        0x2d, 0xd7, 0xc3, 0x68, 0xb4, 0x57, 0xf2, 0x90, 0xec, 0xa3, 0xf3, 0x73, 0x05, 0xf3, 0x98,
        0x6c, 0x6c, 0x78, 0x62, 0x62, 0xfe, 0xed, 0x8a, 0xe9, 0xbd, 0x65, 0x81, 0xb3, 0xaf, 0x5e,
        0xd0, 0xa9,
    ];
    const PASSWORD_TAG: [u8; 16] = [
        0x3a, 0x64, 0xb4, 0x3e, 0xf2, 0xe7, 0x61, 0x04, 0x73, 0xba, 0xf3, 0x93, 0x00, 0xb5, 0x03,
        0x74,
    ];

    const FLAT: BundleKind = BundleKind::Flat {
        virtual_size: 8 << 20,
        chunk_size: 1 << 20,
        sector_size: 512,
    };

    fn none_meta() -> CipherMeta {
        CipherMeta {
            cipher: CipherAlg::ChaCha12,
            nonce: DATA_NONCE,
            key_id: KEY_ID,
            slot: KeySlot {
                kdf: KdfKind::None,
                iterations: None,
                salt: SALT,
                wrap_nonce: WRAP_NONCE,
                wrapped_key: [0u8; 32],
                tag: [0u8; 16],
            },
        }
    }

    fn password_meta() -> CipherMeta {
        CipherMeta {
            cipher: CipherAlg::ChaCha20,
            nonce: PASSWORD_DATA_NONCE,
            key_id: KEY_ID,
            slot: KeySlot {
                kdf: KdfKind::Pbkdf2HmacSha256,
                iterations: Some(PASSWORD_ITERATIONS),
                salt: PASSWORD_SALT,
                wrap_nonce: PASSWORD_WRAP_NONCE,
                wrapped_key: [0u8; 32],
                tag: [0u8; 16],
            },
        }
    }

    /// Assert that the keyslot tag rejects this (kind, metadata, KEK) triple.
    fn rejects(kind: &BundleKind, meta: &CipherMeta, kek: &CipherKey) {
        assert_eq!(
            unwrap_slot(kind, meta, kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );
    }

    #[test]
    fn key_id_matches_fixed_vector() {
        assert_eq!(key_id(&key(VMK)), KEY_ID);
    }

    #[test]
    fn key_id_is_not_the_manifest_key_id_by_accident() {
        // A different VMK must not collide with the fixed value.
        let mut other = VMK;
        other[0] ^= 1;
        assert_ne!(key_id(&key(other)), KEY_ID);
    }

    #[test]
    fn pbkdf2_derive_kek_matches_fixed_vector() {
        let slot = password_meta().slot;
        let kek = derive_kek(&slot, Some(PASSWORD), None).unwrap();
        assert_eq!(kek.as_bytes(), &KEK_PBKDF2);
        assert_eq!(
            derive_kek(&slot, None, Some(&key(KEK_PBKDF2))).err(),
            Some(KeyslotError::MissingPassword)
        );
    }

    #[test]
    fn none_derive_kek_returns_the_supplied_key() {
        let slot = none_meta().slot;
        let kek = derive_kek(&slot, None, Some(&key(KEK_NONE))).unwrap();
        assert_eq!(kek.as_bytes(), &KEK_NONE);
        assert_eq!(
            derive_kek(&slot, Some(b"ignored"), None).err(),
            Some(KeyslotError::MissingKeyFile)
        );
    }

    #[test]
    fn rejects_a_mismatched_key_id_even_with_a_valid_tag() {
        let mut meta = none_meta();
        // A tag computed over a wrong key id still verifies; the VMK
        // fingerprint check must reject the unwrap.
        meta.key_id = [0u8; 8];
        wrap_slot(&FLAT, &mut meta, &key(KEK_NONE), &key(VMK)).unwrap();
        rejects(&FLAT, &meta, &key(KEK_NONE));
    }

    #[test]
    fn wrap_and_unwrap_match_fixed_vectors() {
        let mut meta = none_meta();
        wrap_slot(&FLAT, &mut meta, &key(KEK_NONE), &key(VMK)).unwrap();
        assert_eq!(meta.slot.wrapped_key, WRAPPED_NONE);
        assert_eq!(meta.slot.tag, TAG_NONE);

        let vmk = unwrap_slot(&FLAT, &meta, &key(KEK_NONE)).unwrap();
        assert_eq!(vmk.as_bytes(), &VMK);
    }

    #[test]
    fn pbkdf2_wrap_and_unwrap_match_fixed_vectors() {
        let kind = BundleKind::Image {
            size: 34_359_738_368,
        };
        let mut meta = password_meta();
        let kek = derive_kek(&meta.slot, Some(PASSWORD), None).unwrap();
        wrap_slot(&kind, &mut meta, &kek, &key(VMK)).unwrap();
        assert_eq!(meta.slot.wrapped_key, PASSWORD_WRAPPED);
        assert_eq!(meta.slot.tag, PASSWORD_TAG);

        let vmk = unwrap_slot(&kind, &meta, &kek).unwrap();
        assert_eq!(vmk.as_bytes(), &VMK);
    }

    #[test]
    fn wrong_kek_fails_the_tag() {
        let mut meta = none_meta();
        wrap_slot(&FLAT, &mut meta, &key(KEK_NONE), &key(VMK)).unwrap();
        let mut wrong = KEK_NONE;
        wrong[0] ^= 0xFF;
        rejects(&FLAT, &meta, &key(wrong));
    }

    #[test]
    fn tag_binds_every_keyslot_and_identity_field() {
        let mut base = none_meta();
        wrap_slot(&FLAT, &mut base, &key(KEK_NONE), &key(VMK)).unwrap();
        let kek = key(KEK_NONE);

        // Keyslot-field tampering.
        let mut tampered = base;
        tampered.slot.wrapped_key[0] ^= 1;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        let mut tampered = base;
        tampered.slot.wrap_nonce[0] ^= 1;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        let mut tampered = base;
        tampered.slot.salt[0] ^= 1;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        // Identity/parameter tampering.
        let mut tampered = base;
        tampered.cipher = CipherAlg::ChaCha20;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        let mut tampered = base;
        tampered.nonce[0] ^= 1;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        let mut tampered = base;
        tampered.key_id[0] ^= 1;
        assert_eq!(
            unwrap_slot(&FLAT, &tampered, &kek).err(),
            Some(KeyslotError::WrongPasswordOrCorruptKeyslot)
        );

        let other_geometry = BundleKind::Flat {
            virtual_size: (8 << 20) + 512,
            chunk_size: 1 << 20,
            sector_size: 512,
        };
        rejects(&other_geometry, &base, &kek);

        let other_kind = BundleKind::Image { size: 8 << 20 };
        rejects(&other_kind, &base, &kek);
    }

    #[test]
    fn tag_binds_iterations() {
        let mut meta = password_meta();
        let kek = key(KEK_PBKDF2);
        wrap_slot(
            &BundleKind::Image {
                size: 34_359_738_368,
            },
            &mut meta,
            &kek,
            &key(VMK),
        )
        .unwrap();
        let mut tampered = meta;
        tampered.slot.iterations = Some(PASSWORD_ITERATIONS + 1);
        rejects(
            &BundleKind::Image {
                size: 34_359_738_368,
            },
            &tampered,
            &kek,
        );
    }

    #[test]
    fn same_kek_with_new_salt_and_wrap_nonce_changes_wrapped_key_and_tag() {
        let mut first = none_meta();
        wrap_slot(&FLAT, &mut first, &key(KEK_NONE), &key(VMK)).unwrap();

        let mut second = first;
        second.slot.salt = [
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
            0xde, 0xdf,
        ];
        second.slot.wrap_nonce = [0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7];
        wrap_slot(&FLAT, &mut second, &key(KEK_NONE), &key(VMK)).unwrap();

        assert_eq!(second.slot.wrapped_key, WRAPPED_NONE_ALT);
        assert_eq!(second.slot.tag, TAG_NONE_ALT);
        assert_ne!(first.slot.wrapped_key, second.slot.wrapped_key);
        assert_ne!(first.slot.tag, second.slot.tag);

        let vmk = unwrap_slot(&FLAT, &second, &key(KEK_NONE)).unwrap();
        assert_eq!(vmk.as_bytes(), &VMK);
    }

    #[test]
    fn error_display_and_error_impls() {
        fn assert_error<T: core::error::Error>() {}
        assert_error::<KeyslotError>();
        assert!(!KeyslotError::MissingPassword.to_string().is_empty());
        assert!(!KeyslotError::MissingKeyFile.to_string().is_empty());
        assert!(!KeyslotError::WrongPasswordOrCorruptKeyslot
            .to_string()
            .is_empty());
        assert!(!KeyslotError::Crypto.to_string().is_empty());
    }

    /// Keep the hex helper used above honest: the constants are written as
    /// byte arrays, but a single unhex round-trip catches a typo in a literal.
    #[test]
    fn fixed_vector_hex_roundtrip() {
        assert_eq!(
            unhex::<8>("a3267f36cdedf59f"),
            KEY_ID,
            "key_id constant mismatch"
        );
        assert_eq!(
            unhex::<32>("a5ce4ac9ffd189d635193eae97d84dd9f0cfc93fb727a08aac15ecbb06946c9b"),
            WRAPPED_NONE
        );
        assert_eq!(unhex::<16>("4161e8b4c82185d1f0b02addfef9d240"), TAG_NONE);
        assert_eq!(
            unhex::<32>("2dd7c368b457f290eca3f37305f3986c6c786262feed8ae9bd6581b3af5ed0a9"),
            PASSWORD_WRAPPED
        );
        assert_eq!(
            unhex::<16>("3a64b43ef2e7610473baf39300b50374"),
            PASSWORD_TAG
        );
    }
}
