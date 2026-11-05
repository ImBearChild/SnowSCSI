//! CLI cipher selection and keyslot handling.
//!
//! The library supplies the length-preserving plane decorators, the ciphers and
//! the keyslot primitives; this module only chooses a cipher from a manifest's
//! [`CipherMeta`] and turns a credential (a password or a raw 32-byte key file)
//! into a keyslot or an unlocked volume master key (VMK). It never logs key
//! material and does not keep a password.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use snowscsi::common::bundle::{BundleKind, CipherAlg, CipherMeta, KdfKind, KeySlot};
use snowscsi::common::cipher::keyslot::{derive_kek, key_id, unwrap_slot, wrap_slot, KeyslotError};
use snowscsi::common::cipher::{
    AesCtr, BlockCipher16, ChaCha12, ChaCha20, ChaCha8, CipherError, CipherKey, CtrAccel,
    NonceCipher, StreamCipher, XorMix,
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
    /// Build the manifest's stream cipher from an unlocked VMK.
    pub fn from_meta(meta: &CipherMeta, vmk: &CipherKey) -> Result<Self, String> {
        let nonce = meta.nonce;
        Ok(match meta.cipher {
            CipherAlg::ChaCha8 => Self::ChaCha8(
                ChaCha8::new(vmk, nonce).map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::ChaCha12 => Self::ChaCha12(
                ChaCha12::new(vmk, nonce)
                    .map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::ChaCha20 => Self::ChaCha20(
                ChaCha20::new(vmk, nonce)
                    .map_err(|e| format!("{}: {e}", cipher_meta_name(meta)))?,
            ),
            CipherAlg::AesCtr => Self::Aes(Box::new(AesCtr::new(SoftAes256::new(vmk), nonce))),
            CipherAlg::Xor => Self::Xor(XorMix::new(vmk, nonce)),
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

/// One credential for a keyslot.
///
/// Exactly one of the two variants is present. There is deliberately no
/// [`Debug`] implementation: it would make a password or key easy to leak into
/// a log line.
pub enum Credential {
    /// A password for a PBKDF2 keyslot.
    Password(Vec<u8>),
    /// A raw 32-byte key for a `kdf = none` keyslot.
    Key(CipherKey),
}

impl Credential {
    /// Borrow the password, when this is a password credential.
    pub fn password(&self) -> Option<&[u8]> {
        match self {
            Self::Password(password) => Some(password),
            Self::Key(_) => None,
        }
    }

    /// Borrow the raw key, when this is a key-file credential.
    pub fn key(&self) -> Option<&CipherKey> {
        match self {
            Self::Key(key) => Some(key),
            Self::Password(_) => None,
        }
    }

    /// Best-effort wipe of the stored password (not `zeroize`).
    pub fn wipe(&mut self) {
        if let Self::Password(password) = self {
            crate::wipe(password);
        }
    }
}

/// Read the user-supplied credential.
///
/// `--password-file` supplies one password line, `--key-file` an exact 32-byte
/// key; the two are mutually exclusive. Without either flag the password is
/// read from stdin; `confirm` reads a second line and requires a match (a pipe
/// works, an EOF without a TTY is an error).
pub fn read_credential(
    password_file: Option<&str>,
    key_file: Option<&str>,
    confirm: bool,
) -> Result<Credential, String> {
    match (password_file, key_file) {
        (Some(_), Some(_)) => {
            Err("--password-file and --key-file are mutually exclusive".to_string())
        }
        (Some(path), None) => crate::read_password_file(path).map(Credential::Password),
        (None, Some(path)) => read_key_file(path).map(Credential::Key),
        (None, None) => {
            let mut first = crate::read_password_prompt()?;
            if confirm {
                let mut second = crate::read_password_prompt()?;
                if first != second {
                    crate::wipe(&mut first);
                    crate::wipe(&mut second);
                    return Err("passwords do not match".to_string());
                }
            }
            Ok(Credential::Password(first))
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
    let key = CipherKey::from_bytes(&bytes).map_err(|e| format!("key file '{path}': {e}"));
    // Best effort (not zeroize): wipe the raw file buffer.
    crate::wipe(&mut bytes);
    key
}

/// Parse a manifest-spelling cipher algorithm name.
pub fn parse_alg(name: &str) -> Result<CipherAlg, String> {
    match name {
        "chacha8" => Ok(CipherAlg::ChaCha8),
        "chacha12" => Ok(CipherAlg::ChaCha12),
        "chacha20" => Ok(CipherAlg::ChaCha20),
        "aes-ctr" => Ok(CipherAlg::AesCtr),
        "xor" => Ok(CipherAlg::Xor),
        other => Err(format!(
            "unknown cipher '{other}' (expected chacha8, chacha12, chacha20, aes-ctr, or xor)"
        )),
    }
}

/// Fill `buf` from the operating system's random source.
///
/// There is deliberately no fallback: a failure to read randomness is a hard
/// error, never a zero nonce/salt.
fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    getrandom::fill(buf).map_err(|e| format!("cannot read random bytes: {e}"))
}

/// Generate a fresh 8-byte nonce.
pub fn random_nonce() -> Result<[u8; 8], String> {
    let mut nonce = [0u8; 8];
    random_bytes(&mut nonce)?;
    Ok(nonce)
}

/// Generate a fresh 16-byte keyslot salt.
pub fn random_salt() -> Result<[u8; 16], String> {
    let mut salt = [0u8; 16];
    random_bytes(&mut salt)?;
    Ok(salt)
}

/// Build a fresh random VMK wrapped for `credential`.
///
/// `nonce` is the payload data nonce (the caller generates it separately);
/// `salt` and `wrap_nonce` are always fresh. `iterations` is required for
/// PBKDF2 and rejected for `kdf = none`. Returns the manifest block plus the
/// VMK for the immediate encryption/decryption caller.
pub fn new_keyslot(
    cipher: CipherAlg,
    nonce: [u8; 8],
    kdf: KdfKind,
    iterations: Option<u32>,
    credential: &Credential,
    kind: &BundleKind,
) -> Result<(CipherMeta, CipherKey), String> {
    let iterations = match kdf {
        KdfKind::Pbkdf2HmacSha256 => {
            let iterations =
                iterations.ok_or_else(|| "PBKDF2 requires an iteration count".to_string())?;
            if !(1_000..=2_000_000).contains(&iterations) {
                return Err(format!(
                    "invalid PBKDF2 iteration count {iterations} (1000..=2000000)"
                ));
            }
            Some(iterations)
        }
        KdfKind::None => {
            if iterations.is_some() {
                return Err("kdf = none does not take an iteration count".to_string());
            }
            None
        }
    };

    let mut vmk_bytes = [0u8; 32];
    random_bytes(&mut vmk_bytes)?;
    let vmk = CipherKey::from_bytes(&vmk_bytes).map_err(|e| e.to_string())?;
    crate::wipe(&mut vmk_bytes);

    let salt = random_salt()?;
    let wrap_nonce = random_nonce()?;
    let key_id = key_id(&vmk);
    let mut meta = CipherMeta {
        cipher,
        nonce,
        key_id,
        slot: KeySlot {
            kdf,
            iterations,
            salt,
            wrap_nonce,
            wrapped_key: [0u8; 32],
            tag: [0u8; 16],
        },
    };
    let kek = derive_kek(&meta.slot, credential.password(), credential.key())
        .map_err(|e| format!("cannot derive the keyslot key: {e}"))?;
    wrap_slot(kind, &mut meta, &kek, &vmk).map_err(|e| format!("cannot wrap the keyslot: {e}"))?;
    Ok((meta, vmk))
}

/// Unlock a manifest's VMK with `credential`.
///
/// The tag is verified before the key is unwrapped: a wrong password or a
/// tampered keyslot/identity fails here instead of yielding a wrong VMK.
pub fn unlock(
    meta: &CipherMeta,
    kind: &BundleKind,
    credential: &Credential,
) -> Result<CipherKey, String> {
    let kek = derive_kek(&meta.slot, credential.password(), credential.key())
        .map_err(|e| format!("cannot derive the keyslot key: {e}"))?;
    unwrap_slot(kind, meta, &kek).map_err(|e| match e {
        KeyslotError::WrongPasswordOrCorruptKeyslot => {
            "wrong password or corrupt keyslot".to_string()
        }
        other => format!("cannot unwrap the keyslot: {other}"),
    })
}

/// Re-wrap an existing VMK under a new credential, changing only the keyslot.
///
/// The data cipher, data nonce and key id are copied from `old`; only
/// `kdf`/`iterations`/`salt`/`wrap_nonce`/`wrapped_key`/`tag` change. The
/// caller must verify the result with [`unlock`] before publishing it.
pub fn rewrap_keyslot(
    kind: &BundleKind,
    old: &CipherMeta,
    old_credential: &Credential,
    new_kdf: KdfKind,
    new_iterations: Option<u32>,
    new_credential: &Credential,
) -> Result<(CipherMeta, CipherKey), String> {
    let iterations = match new_kdf {
        KdfKind::Pbkdf2HmacSha256 => {
            let iterations =
                new_iterations.ok_or_else(|| "PBKDF2 requires an iteration count".to_string())?;
            if !(1_000..=2_000_000).contains(&iterations) {
                return Err(format!(
                    "invalid PBKDF2 iteration count {iterations} (1000..=2000000)"
                ));
            }
            Some(iterations)
        }
        KdfKind::None => {
            if new_iterations.is_some() {
                return Err("kdf = none does not take an iteration count".to_string());
            }
            None
        }
    };
    let vmk = unlock(old, kind, old_credential)?;
    let salt = random_salt()?;
    let wrap_nonce = random_nonce()?;
    let mut new = CipherMeta {
        cipher: old.cipher,
        nonce: old.nonce,
        key_id: old.key_id,
        slot: KeySlot {
            kdf: new_kdf,
            iterations,
            salt,
            wrap_nonce,
            wrapped_key: [0u8; 32],
            tag: [0u8; 16],
        },
    };
    let kek = derive_kek(&new.slot, new_credential.password(), new_credential.key())
        .map_err(|e| format!("cannot derive the new keyslot key: {e}"))?;
    wrap_slot(kind, &mut new, &kek, &vmk)
        .map_err(|e| format!("cannot wrap the new keyslot: {e}"))?;
    Ok((new, vmk))
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
            nonce: [0x5Au8; 8],
            key_id: [0x33u8; 8],
            slot: KeySlot {
                kdf: KdfKind::None,
                iterations: None,
                salt: [0x11u8; 16],
                wrap_nonce: [0x22u8; 8],
                wrapped_key: [0x44u8; 32],
                tag: [0x55u8; 16],
            },
        }
    }

    fn key() -> CipherKey {
        CipherKey::from_bytes(&[0x42u8; 32]).unwrap()
    }

    fn image_kind() -> BundleKind {
        BundleKind::Image { size: 65_537 }
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
            nonce: unhex::<8>("f0f1f2f3f4f5f6f7"),
            key_id: [0u8; 8],
            slot: meta(CipherAlg::AesCtr).slot,
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
    fn keyslot_round_trips_with_a_password_and_with_a_key_file() {
        // A password keyslot: PBKDF2 (low iteration count for the test).
        let credential = Credential::Password(b"correct horse".to_vec());
        let (meta, vmk) = new_keyslot(
            CipherAlg::ChaCha20,
            [0x5Au8; 8],
            KdfKind::Pbkdf2HmacSha256,
            Some(1_000),
            &credential,
            &image_kind(),
        )
        .unwrap();
        assert_eq!(meta.key_id, key_id(&vmk));
        assert_eq!(meta.slot.kdf, KdfKind::Pbkdf2HmacSha256);
        assert_eq!(meta.slot.iterations, Some(1_000));
        // The VMK is not stored in the clear.
        assert_ne!(meta.slot.wrapped_key, *vmk.as_bytes());
        let unlocked = unlock(&meta, &image_kind(), &credential).unwrap();
        assert_eq!(unlocked.as_bytes(), vmk.as_bytes());

        let wrong = Credential::Password(b"wrong".to_vec());
        let err = unlock(&meta, &image_kind(), &wrong).unwrap_err();
        assert!(err.contains("wrong password"), "{err}");

        // A key-file keyslot reuses `salt` even though the KDF is `none`.
        let path = temp_file("keyslot", &[0x7Au8; 32]);
        let credential = read_credential(None, Some(path.to_str().unwrap()), false).unwrap();
        let (meta, vmk) = new_keyslot(
            CipherAlg::AesCtr,
            [0x11u8; 8],
            KdfKind::None,
            None,
            &credential,
            &image_kind(),
        )
        .unwrap();
        assert_eq!(meta.slot.kdf, KdfKind::None);
        assert_eq!(meta.slot.iterations, None);
        assert_eq!(meta.key_id, key_id(&vmk));
        let unlocked = unlock(&meta, &image_kind(), &credential).unwrap();
        assert_eq!(unlocked.as_bytes(), vmk.as_bytes());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_keyslot_rejects_bad_iterations_and_missing_credentials() {
        let credential = Credential::Password(b"pw".to_vec());
        assert!(new_keyslot(
            CipherAlg::Xor,
            [0u8; 8],
            KdfKind::Pbkdf2HmacSha256,
            None,
            &credential,
            &image_kind(),
        )
        .is_err());
        assert!(new_keyslot(
            CipherAlg::Xor,
            [0u8; 8],
            KdfKind::Pbkdf2HmacSha256,
            Some(999),
            &credential,
            &image_kind(),
        )
        .is_err());
        assert!(new_keyslot(
            CipherAlg::Xor,
            [0u8; 8],
            KdfKind::None,
            Some(1_000),
            &credential,
            &image_kind(),
        )
        .is_err());
        // PBKDF2 without a password is a hard error.
        assert!(new_keyslot(
            CipherAlg::Xor,
            [0u8; 8],
            KdfKind::Pbkdf2HmacSha256,
            Some(1_000),
            &Credential::Key(key()),
            &image_kind(),
        )
        .is_err());
    }

    #[test]
    fn unlock_rejects_a_changed_kind_or_cipher() {
        let credential = Credential::Key(key());
        let kind = BundleKind::Image { size: 4_096 };
        let (meta, _vmk) = new_keyslot(
            CipherAlg::ChaCha12,
            [0u8; 8],
            KdfKind::None,
            None,
            &credential,
            &kind,
        )
        .unwrap();

        assert!(unlock(&meta, &kind, &credential).is_ok());
        assert!(unlock(&meta, &BundleKind::Image { size: 4_097 }, &credential).is_err());
        let mut changed = meta;
        changed.cipher = CipherAlg::ChaCha20;
        assert!(unlock(&changed, &kind, &credential).is_err());
    }

    #[test]
    fn cipher_meta_name_matches_the_manifest_spelling() {
        assert_eq!(cipher_meta_name(&meta(CipherAlg::ChaCha8)), "chacha8");
        assert_eq!(cipher_meta_name(&meta(CipherAlg::AesCtr)), "aes-ctr");
    }

    #[test]
    fn parse_alg_accepts_every_manifest_spelling() {
        for (name, alg) in [
            ("chacha8", CipherAlg::ChaCha8),
            ("chacha12", CipherAlg::ChaCha12),
            ("chacha20", CipherAlg::ChaCha20),
            ("aes-ctr", CipherAlg::AesCtr),
            ("xor", CipherAlg::Xor),
        ] {
            assert_eq!(parse_alg(name), Ok(alg));
        }
        for name in ["", "ChaCha20", "rot13", "aes"] {
            assert!(parse_alg(name).is_err(), "{name}");
        }
    }

    #[test]
    fn created_keyslot_round_trips_through_the_manifest_encoder() {
        for alg in [
            CipherAlg::ChaCha8,
            CipherAlg::ChaCha12,
            CipherAlg::ChaCha20,
            CipherAlg::AesCtr,
            CipherAlg::Xor,
        ] {
            let credential = Credential::Password(b"pw".to_vec());
            let (meta, _vmk) = new_keyslot(
                alg,
                [0x5Au8; 8],
                KdfKind::Pbkdf2HmacSha256,
                Some(1_000),
                &credential,
                &image_kind(),
            )
            .unwrap();
            let bundle = snowscsi::common::bundle::BundleMeta {
                kind: image_kind(),
                cipher: Some(meta),
                has_crc: true,
            };
            let encoded = bundle.encode().unwrap();
            let parsed = snowscsi::common::bundle::BundleMeta::parse(&encoded).unwrap();
            assert_eq!(parsed.cipher, Some(meta));
            assert!(parsed.has_crc);
        }
    }

    #[test]
    fn manifest_bound_is_still_768() {
        assert_eq!(snowscsi::common::bundle::MAX_MANIFEST, 768);
    }
}
