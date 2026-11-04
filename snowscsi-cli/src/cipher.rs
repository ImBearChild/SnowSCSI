//! CLI cipher selection and key derivation.
//!
//! The library supplies the length-preserving plane decorators and the
//! ciphers; this module only chooses one from a manifest's [`CipherMeta`] and
//! turns a password or a raw key file into a [`CipherKey`]. It never logs key
//! material and does not keep a password.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use snowscsi::common::bundle::{CipherAlg, CipherMeta, KdfKind};
use snowscsi::common::cipher::{
    AesCtr, BlockCipher16, ChaCha12, ChaCha20, ChaCha8, CipherError, CipherKey, CtrAccel, Kdf,
    NonceCipher, SoftKdf, StreamCipher, XorMix,
};

/// AES-256 as a [`BlockCipher16`] for `AesCtr`.
pub struct SoftAes256 {
    cipher: aes::Aes256,
}

impl SoftAes256 {
    /// Build the AES key schedule from a 256-bit key.
    pub fn new(key: &CipherKey) -> Self {
        Self {
            cipher: aes::Aes256::new(GenericArray::from_slice(key.as_bytes())),
        }
    }
}

impl BlockCipher16 for SoftAes256 {
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(block));
        Ok(())
    }
}

impl CtrAccel for SoftAes256 {}

/// The cipher chosen by a manifest.
pub enum CliCipher {
    /// ChaCha with 8 rounds.
    ChaCha8(ChaCha8),
    /// ChaCha with 12 rounds.
    ChaCha12(ChaCha12),
    /// ChaCha with 20 rounds.
    ChaCha20(ChaCha20),
    /// AES-256 in counter mode.
    Aes(Box<AesCtr<SoftAes256>>),
    /// Obfuscation-only XOR mixer.
    Xor(XorMix),
}

impl CliCipher {
    /// Build the manifest's stream cipher from an already-derived key.
    pub fn from_meta(meta: &CipherMeta, key: &CipherKey) -> Result<Self, String> {
        let nonce = meta.nonce;
        Ok(match meta.cipher {
            CipherAlg::ChaCha8 => Self::ChaCha8(
                ChaCha8::new(key, nonce).map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::ChaCha12 => Self::ChaCha12(
                ChaCha12::new(key, nonce)
                    .map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::ChaCha20 => Self::ChaCha20(
                ChaCha20::new(key, nonce)
                    .map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::AesCtr => Self::Aes(Box::new(AesCtr::new(SoftAes256::new(key), nonce))),
            CipherAlg::Xor => Self::Xor(XorMix::new(key, nonce)),
        })
    }
}

impl StreamCipher for CliCipher {
    fn xor(&mut self, off: u64, buf: &mut [u8]) -> Result<(), CipherError> {
        match self {
            Self::ChaCha8(cipher) => cipher.xor(off, buf),
            Self::ChaCha12(cipher) => cipher.xor(off, buf),
            Self::ChaCha20(cipher) => cipher.xor(off, buf),
            Self::Aes(cipher) => cipher.xor(off, buf),
            Self::Xor(cipher) => cipher.xor(off, buf),
        }
    }
}

impl NonceCipher for CliCipher {
    fn set_nonce(&mut self, nonce: [u8; 8]) {
        match self {
            Self::ChaCha8(cipher) => cipher.set_nonce(nonce),
            Self::ChaCha12(cipher) => cipher.set_nonce(nonce),
            Self::ChaCha20(cipher) => cipher.set_nonce(nonce),
            Self::Aes(cipher) => cipher.set_nonce(nonce),
            Self::Xor(cipher) => cipher.set_nonce(nonce),
        }
    }
}

/// Derive the manifest's key from the supplied material.
///
/// PBKDF2 needs a password (`--password-file` or the stdin prompt); `kdf =
/// none` needs an explicit 32-byte key file (`key=<path>`).
pub fn derive_key(
    meta: &CipherMeta,
    password: Option<&[u8]>,
    key_path: Option<&str>,
) -> Result<CipherKey, String> {
    match meta.kdf {
        KdfKind::Pbkdf2HmacSha256 => {
            let password = password.ok_or_else(|| {
                format!(
                    "{} manifest uses PBKDF2; pass --password-file <path>",
                    cipher_meta_name(meta)
                )
            })?;
            let iterations = meta
                .iterations
                .ok_or_else(|| "manifest cipher block is missing `iterations`".to_string())?;
            let salt = meta
                .salt
                .ok_or_else(|| "manifest cipher block is missing `salt`".to_string())?;
            let mut key = [0u8; 32];
            SoftKdf
                .derive(password, &salt, iterations, &mut key)
                .map_err(|e| format!("PBKDF2 key derivation failed: {e}"))?;
            CipherKey::from_bytes(&key).map_err(|e| e.to_string())
        }
        KdfKind::None => {
            let path = key_path.ok_or_else(|| {
                format!(
                    "{} manifest uses kdf = none; pass key=<path> on the LUN spec",
                    cipher_meta_name(meta)
                )
            })?;
            read_key_file(path)
        }
    }
}

/// Read a raw 32-byte key file.
///
/// The length is exact: a trailing newline is **not** stripped, because a key
/// file is binary material, not a password.
pub fn read_key_file(path: &str) -> Result<CipherKey, String> {
    use std::io::Read as _;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("cannot read key file '{path}': {e}"))?;
    let file_len = file
        .metadata()
        .map_err(|e| format!("cannot stat key file '{path}': {e}"))?
        .len();
    if file_len != 32 {
        return Err(format!(
            "key file '{path}' must be exactly 32 bytes (got {file_len})"
        ));
    }
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("cannot read key file '{path}': {e}"))?;
    CipherKey::from_bytes(&bytes).map_err(|e| format!("key file '{path}': {e}"))
}

/// Manifest spelling of the cipher algorithm, for messages.
pub fn cipher_meta_name(meta: &CipherMeta) -> &'static str {
    match meta.cipher {
        CipherAlg::ChaCha8 => "chacha8",
        CipherAlg::ChaCha12 => "chacha12",
        CipherAlg::ChaCha20 => "chacha20",
        CipherAlg::AesCtr => "aes-ctr",
        CipherAlg::Xor => "xor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn cli_cipher_is_send() {
        assert_send::<CliCipher>();
    }

    fn meta(cipher: CipherAlg) -> CipherMeta {
        CipherMeta {
            cipher,
            kdf: KdfKind::None,
            iterations: None,
            salt: None,
            nonce: [0x5Au8; 8],
        }
    }

    fn key() -> CipherKey {
        CipherKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn from_meta_constructs_every_algorithm_and_round_trips() {
        let key = key();
        for alg in [
            CipherAlg::ChaCha8,
            CipherAlg::ChaCha12,
            CipherAlg::ChaCha20,
            CipherAlg::AesCtr,
            CipherAlg::Xor,
        ] {
            let mut cipher = CliCipher::from_meta(&meta(alg), &key).expect("construct cipher");
            let plain: [u8; 100] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
            let mut buf = plain;
            cipher.xor(123, &mut buf).unwrap();
            assert_ne!(buf, plain, "{alg:?} must encrypt");
            cipher.xor(123, &mut buf).unwrap();
            assert_eq!(buf, plain, "{alg:?} must decrypt");
        }
    }

    #[test]
    fn cipher_key_length_is_exact() {
        assert!(CipherKey::from_bytes(&[0u8; 31]).is_err());
        assert!(CipherKey::from_bytes(&[0u8; 33]).is_err());
        assert!(CipherKey::from_bytes(&[0u8; 32]).is_ok());
    }

    fn unhex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = (hex.as_bytes()[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (hex.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *byte = (hi << 4) | lo;
        }
        out
    }

    /// The CLI's `SoftAes256` wrapper must reproduce the same AES-256-CTR
    /// reference used by the library tests (counter = nonce || BE64(block),
    /// unaligned head/tail). This would catch a mis-keyed or mis-sized AES.
    #[test]
    fn aes_ctr_matches_reference_at_unaligned_offsets() {
        let key = CipherKey::from_bytes(&unhex::<32>(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ))
        .unwrap();
        let meta = CipherMeta {
            cipher: CipherAlg::AesCtr,
            kdf: KdfKind::None,
            iterations: None,
            salt: None,
            nonce: unhex::<8>("f0f1f2f3f4f5f6f7"),
        };
        let at3: [u8; 32] =
            unhex("4fbf3694c871e1d290c5ba13a7125f28bc6d2414dde799a2f216cf5f827aefda");
        let at15: [u8; 32] =
            unhex("a7125f28bc6d2414dde799a2f216cf5f827aefdadd04ce861a9ef718138d77f3");
        for (off, expected) in [(3u64, at3), (15u64, at15)] {
            let mut cipher = CliCipher::from_meta(&meta, &key).unwrap();
            let mut buf = [0u8; 32];
            cipher.xor(off, &mut buf).unwrap();
            assert_eq!(buf, expected, "offset {off}");
        }
    }

    fn temp_file(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "snowscsi_cipher_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, bytes).expect("write temp key");
        path
    }

    #[test]
    fn derive_key_pbkdf2_requires_a_password() {
        let meta = CipherMeta {
            cipher: CipherAlg::ChaCha20,
            kdf: KdfKind::Pbkdf2HmacSha256,
            iterations: Some(1_000),
            salt: Some([0x11; 16]),
            nonce: [0x22; 8],
        };
        let err = derive_key(&meta, None, None).unwrap_err();
        assert!(err.contains("--password-file"), "{err}");

        let a = derive_key(&meta, Some(b"secret"), None).unwrap();
        let b = derive_key(&meta, Some(b"secret"), None).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        let other = derive_key(&meta, Some(b"other"), None).unwrap();
        assert_ne!(a.as_bytes(), other.as_bytes());
    }

    #[test]
    fn derive_key_none_requires_a_key_file() {
        let meta = meta(CipherAlg::Xor);
        let err = derive_key(&meta, Some(b"unused"), None).unwrap_err();
        assert!(err.contains("key=<path>"), "{err}");

        let path = temp_file("key32", &[0x7Au8; 32]);
        let key = derive_key(&meta, None, Some(path.to_str().unwrap())).unwrap();
        assert_eq!(key.as_bytes(), &[0x7Au8; 32]);

        // A key file is exact: no trailing-newline tolerance.
        let short = temp_file("key31", &[0u8; 31]);
        assert!(derive_key(&meta, None, Some(short.to_str().unwrap())).is_err());
        let newline = {
            let mut bytes = vec![0u8; 32];
            bytes.push(b'\n');
            temp_file("key33", &bytes)
        };
        assert!(derive_key(&meta, None, Some(newline.to_str().unwrap())).is_err());

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(short);
        let _ = std::fs::remove_file(newline);
    }

    #[test]
    fn cipher_meta_name_matches_the_manifest_spelling() {
        assert_eq!(cipher_meta_name(&meta(CipherAlg::ChaCha8)), "chacha8");
        assert_eq!(cipher_meta_name(&meta(CipherAlg::AesCtr)), "aes-ctr");
    }
}
