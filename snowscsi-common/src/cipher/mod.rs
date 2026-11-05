//! Length-preserving stream-cipher decorators for the byte-plane seams.
//!
//! This module adds an offset-addressed encryption layer that sits **between**
//! a transport and any [`FlatData`]/[`WritableFlatData`] plane
//! ([`CipherPlane`]) or, with `async-io`, between a transport and any
//! `AsyncFlatData`/`AsyncWritableFlatData` plane (`AsyncCipherPlane`).
//! The decorator writes the ciphertext where the plaintext would have gone and
//! reads it back the same way, so a device sees the same geometry it always
//! did.
//!
//! # No in-image header
//!
//! Encryption is **length-preserving**: no sector header, trailer or reserved
//! block is added to the image, and the plaintext length equals the ciphertext
//! length. Everything the cipher needs (key, nonce, block size) lives outside
//! the image, in the plane wrapper. An image written through this module is
//! therefore only readable by a host that already knows the key and nonce —
//! there is no in-band manifest and no format marker.
//!
//! # No integrity
//!
//! CTR and every stream cipher in this module are **malleable**: an attacker
//! who can modify stored bytes can flip the corresponding plaintext bits
//! (and, knowing a plaintext block, forge any other block at a known offset).
//! Nothing here authenticates the image and nothing detects tampering. If
//! integrity matters, put an authenticated layer above this one.
//!
//! # No zeroize
//!
//! Key material is **not** scrubbed. [`CipherKey`] and the cipher state keep
//! the key in ordinary RAM for their whole lifetime; there is no `zeroize`
//! dependency and `Drop` does not wipe the bytes. A caller that needs key
//! scrubbing must supply that itself. The plane wrappers also stage writes
//! through a scratch buffer, so the tail of the most recent plaintext chunk
//! can remain in that buffer; this is the same best-effort (not zeroize)
//! guarantee.
//!
//! # Never reuse a key/nonce pair
//!
//! A key must be used with a **fresh, never-repeated nonce for every image**
//! (and the counter/offset space within one image must not wrap). Reusing a
//! key/nonce pair across two images leaks the XOR of the two plaintexts and
//! breaks the cipher completely. This module cannot enforce that: the caller
//! owns nonce generation and persistence.
//!
//! # Decoration, not a new storage model
//!
//! The wrapper keeps the inner plane's `capacity`, `sync` and error mapping.
//! A failed read never exposes partial or ciphertext bytes (the buffer is
//! zeroed), and an out-of-bounds write is rejected before the backend is
//! touched. The cipher is stateless per call — `xor(off, buf)` is a pure
//! function of the key, nonce, offset and buffer — so the same range always
//! decrypts to the same bytes no matter how it is split across calls.
//!
//! # Why not XTS
//!
//! XTS needs the inverse of a 128-bit block cipher (ChaCha has none) and a
//! whole-data-unit alignment: a partial-unit write would need a
//! read-modify-write round trip or an `Unsupported` result, while the byte
//! seams deliberately allow arbitrary offsets and short transfers. It also
//! provides no authentication, so against an attacker who can copy or restore
//! media it buys little over CTR. CTR keeps position-only addressing, which is
//! what the storage seams need; integrity, if required, belongs in a layer
//! above this one.

use crate::seekable_storage::{FlatData, StorageError, WritableFlatData};

pub mod chacha;
pub mod ctr;
#[cfg(feature = "cipher-kdf")]
pub mod kdf;
#[cfg(feature = "cipher-kdf")]
pub mod keyslot;
pub mod xor;

pub use chacha::{ChaCha, ChaCha12, ChaCha20, ChaCha8};
pub use ctr::{AesCtr, BlockCipher16, CtrAccel};
#[cfg(feature = "cipher-kdf")]
pub use kdf::{pbkdf2_hmac_sha256, Kdf, SoftKdf};
#[cfg(feature = "cipher-kdf")]
pub use keyslot::{derive_kek, key_id, unwrap_slot, wrap_slot, KeyslotError};
pub use xor::XorMix;

/// Offset-addressed stream cipher.
///
/// Implementations are keystream generators: they XOR the keystream at
/// absolute byte offset `off` into `buf` in place. They are stateless with
/// respect to position — producing the keystream for `off` never depends on
/// previous calls — so splitting a range across calls (at any boundary) yields
/// exactly the same bytes as one call over the whole range.
pub trait StreamCipher {
    /// XOR the keystream at absolute byte offset `off` into `buf` in place.
    /// Arbitrary `off` / `buf.len()` (no alignment, never adjust `off`).
    /// `off + buf.len()` must not overflow `u64`.
    /// `xor` applied twice with the same key/nonce is the identity.
    ///
    /// The built-in ciphers validate their parameters in the constructor, so
    /// they cannot fail here; only a fallible backend (`CtrAccel`) can. On
    /// `Err` the buffer is **not** guaranteed untouched: a backend that fails
    /// mid-buffer may already have transformed earlier blocks. Callers that
    /// need all-or-nothing use [`CipherPlane`]/[`AsyncCipherPlane`], which
    /// zero the buffer on any error.
    fn xor(&mut self, off: u64, buf: &mut [u8]) -> Result<(), CipherError>;
}

/// A stream cipher whose nonce can be changed without rebuilding the key.
///
/// Resource-addressed media (a CD-R track table, for example) use one key with
/// a **per-resource nonce domain**: the same key is used for every track, but
/// each track gets its own nonce so no keystream is reused across resources.
/// Changing the nonce never touches the key; a caller must still ensure a
/// `(key, nonce)` pair is never reused for different plaintext.
pub trait NonceCipher: StreamCipher {
    /// Replace the nonce; the key is unchanged.
    fn set_nonce(&mut self, nonce: [u8; 8]);
}

/// Cipher-layer error (no_std, `core::error::Error`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CipherError {
    /// Cipher parameters invalid (unsupported round count, zero KDF
    /// iterations, unaligned CTR batch, offset overflow...). Key *length* is
    /// [`KeyError`], not this.
    BadParameters,
    /// Hardware/accelerated backend failed.
    Backend,
}

impl core::fmt::Display for CipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadParameters => write!(f, "invalid cipher parameters"),
            Self::Backend => write!(f, "cipher backend failed"),
        }
    }
}

impl core::error::Error for CipherError {}

impl From<CipherError> for StorageError {
    fn from(e: CipherError) -> Self {
        match e {
            CipherError::BadParameters => Self::Io(embedded_io::ErrorKind::InvalidInput),
            CipherError::Backend => Self::Io(embedded_io::ErrorKind::Other),
        }
    }
}

/// A 256-bit cipher key.
///
/// Deliberately **not** `Clone`/`Copy` and with a redacted [`Debug`]
/// implementation, so a key is not duplicated by accident or leaked through a
/// log line. The bytes are not scrubbed on drop (see the module docs).
///
/// [`Debug`]: core::fmt::Debug
pub struct CipherKey {
    key: [u8; 32],
}

impl CipherKey {
    /// Wrap exactly 32 key bytes.
    ///
    /// Any other length is [`KeyError::BadLength`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeyError::BadLength { got: bytes.len() })?;
        Ok(Self { key })
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl core::fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherKey(<redacted>)")
    }
}

/// [`CipherKey::from_bytes`] rejected the supplied length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyError {
    /// The key was not exactly 32 bytes long.
    BadLength {
        /// Number of bytes supplied.
        got: usize,
    },
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength { got } => {
                write!(f, "invalid cipher key length: got {got} bytes, expected 32")
            }
        }
    }
}

impl core::error::Error for KeyError {}

/// Encrypting view over any [`FlatData`]/[`WritableFlatData`] plane.
///
/// Reads decrypt in place; writes encrypt in place; `capacity` and `sync`
/// delegate unchanged. Writes are staged through a fixed `SCRATCH`-byte stack
/// buffer (never `alloc`) so the ciphertext handed to the backend is always
/// offset-consistent with the keystream the cipher used.
///
/// Out-of-bounds writes and fills are rejected up front, before any backend
/// call. A failed read zeroes the caller's buffer, and a failed cipher zeroes
/// it too, so a transport never sees a mix of plaintext, ciphertext and
/// garbage. A *backend* failure part-way through a write can still leave the
/// earlier chunks written (always ciphertext, never plaintext); writes are
/// not transactional across chunks.
pub struct CipherPlane<D, C, const SCRATCH: usize = 2048> {
    inner: D,
    cipher: C,
    scratch: [u8; SCRATCH],
}

impl<D, C, const SCRATCH: usize> CipherPlane<D, C, SCRATCH> {
    /// Wrap `inner` with `cipher`, staging writes through an `SCRATCH`-byte
    /// buffer.
    ///
    /// # Panics
    ///
    /// Panics if `SCRATCH == 0`: a zero-length staging buffer would make the
    /// chunked write loop spin forever, so the invariant is checked once here
    /// rather than per write.
    pub fn new(inner: D, cipher: C) -> Self {
        assert!(
            SCRATCH > 0,
            "CipherPlane requires a non-zero SCRATCH buffer"
        );
        Self {
            inner,
            cipher,
            scratch: [0u8; SCRATCH],
        }
    }

    /// Give back the wrapped plane and the cipher.
    pub fn into_parts(self) -> (D, C) {
        (self.inner, self.cipher)
    }

    /// Borrow the wrapped plane.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Mutably borrow the wrapped plane.
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }
}

impl<D: FlatData, C: StreamCipher, const SCRATCH: usize> FlatData for CipherPlane<D, C, SCRATCH> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        if let Err(e) = self.inner.read_at(off, buf) {
            // The backend may have written a partial (ciphertext) prefix.
            buf.fill(0);
            return Err(e);
        }
        if let Err(e) = self.cipher.xor(off, buf) {
            buf.fill(0);
            return Err(e.into());
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
}

impl<D: WritableFlatData, C: StreamCipher, const SCRATCH: usize> WritableFlatData
    for CipherPlane<D, C, SCRATCH>
{
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        // Reject atomically: nothing is staged or written on a bad range.
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.inner.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let mut pos = 0;
        let mut cur = off;
        while pos < buf.len() {
            let n = core::cmp::min(buf.len() - pos, SCRATCH);
            let chunk = &mut self.scratch[..n];
            chunk.copy_from_slice(&buf[pos..pos + n]);
            self.cipher.xor(cur, chunk).map_err(StorageError::from)?;
            self.inner.write_at(cur, chunk)?;
            pos += n;
            cur = cur.wrapping_add(n as u64);
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        self.inner.sync()
    }

    /// Overrides the 512-byte default with the cipher's own chunk size: the
    /// ciphertext of a constant byte is not constant, so the fill must be
    /// encrypted chunk by chunk at the right offsets.
    fn fill_at(&mut self, off: u64, mut len: u64, byte: u8) -> Result<(), StorageError> {
        let end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
        if end > self.inner.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let mut cur = off;
        while len > 0 {
            let n = core::cmp::min(len, SCRATCH as u64) as usize;
            let chunk = &mut self.scratch[..n];
            chunk.fill(byte);
            self.cipher.xor(cur, chunk).map_err(StorageError::from)?;
            self.inner.write_at(cur, chunk)?;
            cur = cur.wrapping_add(n as u64);
            len -= n as u64;
        }
        Ok(())
    }
}

/// Encrypting view over any [`AsyncFlatData`]/[`AsyncWritableFlatData`] plane.
///
/// The asynchronous mirror of [`CipherPlane`]: same up-front bounds check,
/// same zero-on-error policy, same `SCRATCH` chunking. The fill loop yields
/// once per chunk via `crate::async_seekable_storage::yield_now`, so a backend
/// that completes synchronously cannot monopolise the executor across a large
/// fill.
///
/// [`AsyncFlatData`]: crate::async_seekable_storage::AsyncFlatData
/// [`AsyncWritableFlatData`]: crate::async_seekable_storage::AsyncWritableFlatData
#[cfg(feature = "async-io")]
pub struct AsyncCipherPlane<D, C, const SCRATCH: usize = 2048> {
    inner: D,
    cipher: C,
    scratch: [u8; SCRATCH],
}

#[cfg(feature = "async-io")]
impl<D, C, const SCRATCH: usize> AsyncCipherPlane<D, C, SCRATCH> {
    /// Wrap `inner` with `cipher`, staging writes through an `SCRATCH`-byte
    /// buffer.
    ///
    /// # Panics
    ///
    /// Panics if `SCRATCH == 0` (a zero-length staging buffer would make the
    /// chunked loops spin forever).
    pub fn new(inner: D, cipher: C) -> Self {
        assert!(
            SCRATCH > 0,
            "AsyncCipherPlane requires a non-zero SCRATCH buffer"
        );
        Self {
            inner,
            cipher,
            scratch: [0u8; SCRATCH],
        }
    }

    /// Give back the wrapped plane and the cipher.
    pub fn into_parts(self) -> (D, C) {
        (self.inner, self.cipher)
    }

    /// Borrow the wrapped plane.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Mutably borrow the wrapped plane.
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }
}

#[cfg(feature = "async-io")]
impl<D, C, const SCRATCH: usize> crate::async_seekable_storage::AsyncFlatData
    for AsyncCipherPlane<D, C, SCRATCH>
where
    D: crate::async_seekable_storage::AsyncFlatData,
    C: StreamCipher,
{
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        if let Err(e) = self.inner.read_at(off, buf).await {
            buf.fill(0);
            return Err(e);
        }
        if let Err(e) = self.cipher.xor(off, buf) {
            buf.fill(0);
            return Err(e.into());
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
}

#[cfg(feature = "async-io")]
impl<D, C, const SCRATCH: usize> crate::async_seekable_storage::AsyncWritableFlatData
    for AsyncCipherPlane<D, C, SCRATCH>
where
    D: crate::async_seekable_storage::AsyncWritableFlatData,
    C: StreamCipher,
{
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.inner.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let mut pos = 0;
        let mut cur = off;
        while pos < buf.len() {
            let n = core::cmp::min(buf.len() - pos, SCRATCH);
            let chunk = &mut self.scratch[..n];
            chunk.copy_from_slice(&buf[pos..pos + n]);
            self.cipher.xor(cur, chunk).map_err(StorageError::from)?;
            self.inner.write_at(cur, chunk).await?;
            pos += n;
            cur = cur.wrapping_add(n as u64);
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        self.inner.sync().await
    }

    async fn fill_at(&mut self, off: u64, mut len: u64, byte: u8) -> Result<(), StorageError> {
        let end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
        if end > self.inner.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let mut cur = off;
        while len > 0 {
            let n = core::cmp::min(len, SCRATCH as u64) as usize;
            let chunk = &mut self.scratch[..n];
            chunk.fill(byte);
            self.cipher.xor(cur, chunk).map_err(StorageError::from)?;
            self.inner.write_at(cur, chunk).await?;
            cur = cur.wrapping_add(n as u64);
            len -= n as u64;
            crate::async_seekable_storage::yield_now().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seekable_storage::RamBackend;

    /// Test-only stream cipher: every byte is XORed with an offset-dependent
    /// pattern, so a wrong offset (or a wrong chunk boundary) is immediately
    /// visible and failures are easy to read.
    struct PatternCipher;

    fn pattern_byte(pos: u64) -> u8 {
        (pos.wrapping_mul(131) ^ (pos >> 7) ^ 0x5A) as u8
    }

    impl StreamCipher for PatternCipher {
        fn xor(&mut self, off: u64, buf: &mut [u8]) -> Result<(), CipherError> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= pattern_byte(off.wrapping_add(i as u64));
            }
            Ok(())
        }
    }

    /// Independently encrypt `plain` at `off` into `out` (lengths must match).
    fn encrypt_ref(off: u64, plain: &[u8], out: &mut [u8]) {
        out.copy_from_slice(plain);
        let mut c = PatternCipher;
        c.xor(off, out).unwrap();
    }

    /// Fails every request, as an accelerated backend would.
    struct FailingCipher;

    impl StreamCipher for FailingCipher {
        fn xor(&mut self, _off: u64, _buf: &mut [u8]) -> Result<(), CipherError> {
            Err(CipherError::Backend)
        }
    }

    struct SyncCounting<'a> {
        data: &'a mut [u8],
        syncs: usize,
    }

    impl FlatData for SyncCounting<'_> {
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
            let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
            let end = start
                .checked_add(buf.len())
                .ok_or(StorageError::OutOfBounds)?;
            if end > self.data.len() {
                return Err(StorageError::OutOfBounds);
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn capacity(&self) -> u64 {
            self.data.len() as u64
        }
    }

    impl WritableFlatData for SyncCounting<'_> {
        fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
            let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
            let end = start
                .checked_add(buf.len())
                .ok_or(StorageError::OutOfBounds)?;
            if end > self.data.len() {
                return Err(StorageError::OutOfBounds);
            }
            self.data[start..end].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&mut self) -> Result<(), StorageError> {
            self.syncs += 1;
            Ok(())
        }
    }

    #[test]
    fn key_length_is_enforced() {
        assert_eq!(
            CipherKey::from_bytes(&[0u8; 31]).unwrap_err().to_string(),
            "invalid cipher key length: got 31 bytes, expected 32"
        );
        assert_eq!(
            CipherKey::from_bytes(&[0u8; 33]).unwrap_err(),
            KeyError::BadLength { got: 33 }
        );
        let key = CipherKey::from_bytes(&[7u8; 32]).unwrap();
        assert_eq!(key.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = CipherKey::from_bytes(&[0xABu8; 32]).unwrap();
        let mut out = [0u8; 64];
        let mut sink = SliceWriter {
            buf: &mut out,
            len: 0,
        };
        use core::fmt::Write as _;
        write!(sink, "{key:?}").unwrap();
        let len = sink.len;
        assert_eq!(&out[..len], b"CipherKey(<redacted>)");
    }

    /// Minimal `fmt::Write` sink so the test module stays `alloc`-free.
    struct SliceWriter<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl core::fmt::Write for SliceWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.len + s.len();
            if end > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    #[test]
    fn cipher_error_maps_to_storage_error() {
        assert_eq!(
            StorageError::from(CipherError::BadParameters),
            StorageError::Io(embedded_io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            StorageError::from(CipherError::Backend),
            StorageError::Io(embedded_io::ErrorKind::Other)
        );
        assert_eq!(
            CipherError::BadParameters.to_string(),
            "invalid cipher parameters"
        );
        assert_eq!(CipherError::Backend.to_string(), "cipher backend failed");
    }

    /// Identity block cipher: CTR exposes the raw counter blocks.
    struct IdentityBlock;

    impl BlockCipher16 for IdentityBlock {
        fn encrypt_block(&mut self, _block: &mut [u8; 16]) -> Result<(), CipherError> {
            Ok(())
        }
    }

    impl CtrAccel for IdentityBlock {}

    /// Pins the `NonceCipher` contract for one cipher constructor:
    /// `set_nonce(n)` is byte-identical to building a fresh cipher with `n`,
    /// a different nonce changes the keystream, and switching back proves the
    /// key survived.
    fn check_nonce_cipher<C, F>(make: F)
    where
        C: NonceCipher,
        F: Fn([u8; 8]) -> C,
    {
        let plain: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let first_nonce = [0x11u8; 8];
        let second_nonce = [0x22u8; 8];

        let mut original = make(first_nonce);
        let mut reference = make(first_nonce);
        let mut other = make(second_nonce);

        let mut first = plain;
        original.xor(37, &mut first).unwrap();
        let mut expected_first = plain;
        reference.xor(37, &mut expected_first).unwrap();
        assert_eq!(first, expected_first);

        let mut changed = plain;
        other.xor(37, &mut changed).unwrap();
        assert_ne!(
            first, changed,
            "a different nonce must change the keystream"
        );

        original.set_nonce(second_nonce);
        let mut after_set = plain;
        original.xor(37, &mut after_set).unwrap();
        assert_eq!(
            after_set, changed,
            "set_nonce must match a fresh cipher with that nonce"
        );

        original.set_nonce(first_nonce);
        let mut restored = plain;
        original.xor(37, &mut restored).unwrap();
        assert_eq!(
            restored, first,
            "set_nonce must not change the key (switching back restores the keystream)"
        );
    }

    #[test]
    fn nonce_cipher_chacha_matches_fresh_construction() {
        let key = CipherKey::from_bytes(&[0x5Au8; 32]).unwrap();
        check_nonce_cipher(|nonce| ChaCha12::new(&key, nonce).unwrap());
        check_nonce_cipher(|nonce| ChaCha20::new(&key, nonce).unwrap());
    }

    #[test]
    fn nonce_cipher_aes_ctr_matches_fresh_construction() {
        check_nonce_cipher(|nonce| AesCtr::new(IdentityBlock, nonce));
    }

    #[test]
    fn nonce_cipher_xor_mix_matches_fresh_construction() {
        let key = CipherKey::from_bytes(&[0xA5u8; 32]).unwrap();
        check_nonce_cipher(|nonce| XorMix::new(&key, nonce));
    }

    #[test]
    fn plane_round_trip_and_capacity() {
        let mut ram = [0u8; 512];
        let mut plain = [0u8; 24];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = i as u8;
        }
        {
            let mut plane =
                CipherPlane::<_, _, 2048>::new(RamBackend::new(&mut ram), PatternCipher);
            assert_eq!(plane.capacity(), 512);
            plane.write_at(100, &plain).unwrap();
            let mut out = [0u8; 24];
            plane.read_at(100, &mut out).unwrap();
            assert_eq!(out, plain);
        }
        // The backing plane holds ciphertext, not plaintext.
        assert_ne!(&ram[100..124], &plain[..]);
        let mut expected = [0u8; 24];
        encrypt_ref(100, &plain, &mut expected);
        assert_eq!(&ram[100..124], &expected[..]);
    }

    /// The write path really encrypts, and it chunks at `SCRATCH` without
    /// changing the resulting bytes when `SCRATCH` is smaller than the write.
    #[test]
    fn plane_write_is_chunked_but_byte_identical() {
        let plain: [u8; 100] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let mut expected = [0u8; 100];
        encrypt_ref(7, &plain, &mut expected);

        for scratch in [64usize, 16, 7] {
            let mut ram = [0u8; 256];
            if scratch == 64 {
                let mut plane =
                    CipherPlane::<_, _, 64>::new(RamBackend::new(&mut ram), PatternCipher);
                plane.write_at(7, &plain).unwrap();
            } else if scratch == 16 {
                let mut plane =
                    CipherPlane::<_, _, 16>::new(RamBackend::new(&mut ram), PatternCipher);
                plane.write_at(7, &plain).unwrap();
            } else {
                let mut plane =
                    CipherPlane::<_, _, 7>::new(RamBackend::new(&mut ram), PatternCipher);
                plane.write_at(7, &plain).unwrap();
            }
            assert_eq!(&ram[7..107], &expected[..], "SCRATCH={scratch}");
            assert!(ram[..7].iter().all(|&x| x == 0), "SCRATCH={scratch}");
            assert!(ram[107..].iter().all(|&x| x == 0), "SCRATCH={scratch}");
        }
    }

    /// Pins the on-disk bytes to an externally computed constant instead of
    /// [`encrypt_ref`] (which reuses the same XOR path and would bless a
    /// wrong offset or a missing encryption step). The constant is
    /// `pattern_byte(7 + i) ^ i` for `i = 0..16`.
    #[test]
    fn plane_write_matches_a_hard_coded_ciphertext() {
        let expected = [
            0xcfu8, 0x43, 0xc3, 0x47, 0xff, 0x7b, 0xfb, 0x77, 0xff, 0x63, 0xe3, 0x67, 0xef, 0x6b,
            0xeb, 0x17,
        ];
        let plain: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut ram = [0u8; 64];
        {
            // SCRATCH 5 forces three staging chunks for 16 bytes at offset 7.
            let mut plane = CipherPlane::<_, _, 5>::new(RamBackend::new(&mut ram), PatternCipher);
            plane.write_at(7, &plain).unwrap();
        }
        assert_eq!(&ram[7..23], &expected[..]);
        assert!(ram[..7].iter().all(|&b| b == 0));
        assert!(ram[23..].iter().all(|&b| b == 0));
    }

    #[test]
    fn plane_fill_at_encrypts_and_crosses_scratch() {
        let mut ram = [0x11u8; 64];
        {
            let mut plane = CipherPlane::<_, _, 8>::new(RamBackend::new(&mut ram), PatternCipher);
            // 20 bytes at offset 3 crosses the 8-byte SCRATCH three times.
            plane.fill_at(3, 20, 0x00).unwrap();
            let mut out = [0xAAu8; 20];
            plane.read_at(3, &mut out).unwrap();
            assert!(out.iter().all(|&x| x == 0));

            // Out of bounds: rejected up front, backend never touched.
            assert_eq!(plane.fill_at(60, 8, 0xAA), Err(StorageError::OutOfBounds));
            assert_eq!(
                plane.fill_at(u64::MAX, 2, 0),
                Err(StorageError::OutOfBounds)
            );
        }
        // Raw backing: ciphertext of a 0x00 fill is the keystream itself.
        let mut keystream = [0u8; 20];
        for (i, b) in keystream.iter_mut().enumerate() {
            *b = pattern_byte(3 + i as u64);
        }
        assert_eq!(&ram[3..23], &keystream[..]);
        assert!(ram[..3].iter().all(|&x| x == 0x11));
        assert!(ram[23..].iter().all(|&x| x == 0x11));
    }

    #[test]
    fn plane_write_out_of_bounds_is_atomic() {
        let mut ram = [0u8; 64];
        {
            let mut plane = CipherPlane::<_, _, 8>::new(RamBackend::new(&mut ram), PatternCipher);
            assert_eq!(
                plane.write_at(60, &[0xFFu8; 8]),
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                plane.write_at(u64::MAX, &[0xFFu8; 2]),
                Err(StorageError::OutOfBounds)
            );
        }
        assert!(ram.iter().all(|&x| x == 0));
    }

    #[test]
    fn plane_unaligned_cross_scratch_round_trip() {
        let mut ram = [0u8; 512];
        let plain: [u8; 100] = core::array::from_fn(|i| (i as u8).wrapping_add(0x40));
        {
            let mut plane = CipherPlane::<_, _, 64>::new(RamBackend::new(&mut ram), PatternCipher);
            plane.write_at(7, &plain).unwrap();
            let mut out = [0u8; 100];
            plane.read_at(7, &mut out).unwrap();
            assert_eq!(out, plain);
        }
    }

    #[test]
    fn plane_read_out_of_bounds_zeroes_buf() {
        let mut ram = [0u8; 64];
        let mut plane = CipherPlane::<_, _, 2048>::new(RamBackend::new(&mut ram), PatternCipher);
        let mut buf = [0xAAu8; 16];
        assert_eq!(plane.read_at(60, &mut buf), Err(StorageError::OutOfBounds));
        assert!(buf.iter().all(|&x| x == 0));
    }

    #[test]
    fn plane_cipher_error_zeroes_buf() {
        let mut ram = [0u8; 64];
        let mut plane = CipherPlane::<_, _, 2048>::new(RamBackend::new(&mut ram), FailingCipher);
        let mut buf = [0xAAu8; 8];
        assert_eq!(
            plane.read_at(0, &mut buf),
            Err(StorageError::Io(embedded_io::ErrorKind::Other))
        );
        assert!(buf.iter().all(|&x| x == 0));

        // The write path maps the cipher error too (and does not write).
        assert_eq!(
            plane.write_at(0, &[1, 2, 3]),
            Err(StorageError::Io(embedded_io::ErrorKind::Other))
        );
    }

    /// Backend that writes a partial garbage prefix and then fails. A real
    /// block backend can do this on a short read; the plane must not expose
    /// the prefix even though the buffer was mutated by the inner call.
    struct DirtyFailBackend {
        len: usize,
    }

    impl FlatData for DirtyFailBackend {
        fn read_at(&mut self, _off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
            let n = buf.len() / 2;
            buf[..n].fill(0xAA);
            Err(StorageError::Io(embedded_io::ErrorKind::Other))
        }

        fn capacity(&self) -> u64 {
            self.len as u64
        }
    }

    #[test]
    fn plane_read_zeroes_buf_when_inner_writes_then_fails() {
        let mut plane = CipherPlane::<_, _, 64>::new(DirtyFailBackend { len: 64 }, PatternCipher);
        let mut buf = [0x55u8; 16];
        assert_eq!(
            plane.read_at(0, &mut buf),
            Err(StorageError::Io(embedded_io::ErrorKind::Other))
        );
        assert!(buf.iter().all(|&x| x == 0));
    }

    #[cfg(feature = "async-io")]
    struct DirtyFailAsync {
        len: usize,
    }

    #[cfg(feature = "async-io")]
    impl crate::async_seekable_storage::AsyncFlatData for DirtyFailAsync {
        async fn read_at(&mut self, _off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
            let n = buf.len() / 2;
            buf[..n].fill(0xBB);
            Err(StorageError::Io(embedded_io::ErrorKind::Other))
        }

        fn capacity(&self) -> u64 {
            self.len as u64
        }
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_plane_read_zeroes_buf_when_inner_writes_then_fails() {
        use crate::async_seekable_storage::AsyncFlatData;

        let mut plane =
            AsyncCipherPlane::<_, _, 64>::new(DirtyFailAsync { len: 64 }, PatternCipher);
        block_on(async {
            let mut buf = [0x55u8; 16];
            assert_eq!(
                AsyncFlatData::read_at(&mut plane, 0, &mut buf).await,
                Err(StorageError::Io(embedded_io::ErrorKind::Other))
            );
            assert!(buf.iter().all(|&x| x == 0));
        });
    }

    #[test]
    fn plane_sync_delegates() {
        let mut data = [0u8; 32];
        let mut plane = CipherPlane::<_, _, 8>::new(
            SyncCounting {
                data: &mut data,
                syncs: 0,
            },
            PatternCipher,
        );
        assert_eq!(plane.sync(), Ok(()));
        assert_eq!(plane.sync(), Ok(()));
        let (inner, _) = plane.into_parts();
        assert_eq!(inner.syncs, 2);
    }

    // ── Asynchronous mirror ─────────────────────────────────────────

    #[cfg(feature = "async-io")]
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_plane_round_trip_and_capacity() {
        use crate::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};

        let mut ram = [0u8; 512];
        let plain: [u8; 100] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        block_on(async {
            let mut plane =
                AsyncCipherPlane::<_, _, 2048>::new(RamBackend::new(&mut ram), PatternCipher);
            assert_eq!(AsyncFlatData::capacity(&plane), 512);
            AsyncWritableFlatData::write_at(&mut plane, 7, &plain)
                .await
                .unwrap();
            let mut out = [0u8; 100];
            AsyncFlatData::read_at(&mut plane, 7, &mut out)
                .await
                .unwrap();
            assert_eq!(out, plain);
            AsyncWritableFlatData::sync(&mut plane).await.unwrap();
        });
        // Raw backing holds the chunked ciphertext.
        let mut expected = [0u8; 100];
        encrypt_ref(7, &plain, &mut expected);
        assert_eq!(&ram[7..107], &expected[..]);
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_plane_fill_crosses_scratch_and_rejects_bounds() {
        use crate::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};

        let mut ram = [0x22u8; 64];
        block_on(async {
            let mut plane =
                AsyncCipherPlane::<_, _, 8>::new(RamBackend::new(&mut ram), PatternCipher);
            AsyncWritableFlatData::fill_at(&mut plane, 3, 20, 0x00)
                .await
                .unwrap();
            let mut out = [0xAAu8; 20];
            AsyncFlatData::read_at(&mut plane, 3, &mut out)
                .await
                .unwrap();
            assert!(out.iter().all(|&x| x == 0));

            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut plane, 60, 8, 0xAA).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut plane, u64::MAX, 2, 0).await,
                Err(StorageError::OutOfBounds)
            );

            // Out-of-bounds write is atomic as well.
            assert_eq!(
                AsyncWritableFlatData::write_at(&mut plane, 60, &[0xFFu8; 8]).await,
                Err(StorageError::OutOfBounds)
            );
        });
        let mut keystream = [0u8; 20];
        for (i, b) in keystream.iter_mut().enumerate() {
            *b = pattern_byte(3 + i as u64);
        }
        assert_eq!(&ram[3..23], &keystream[..]);
        assert!(ram[..3].iter().all(|&x| x == 0x22));
        assert!(ram[23..].iter().all(|&x| x == 0x22));
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_plane_read_out_of_bounds_zeroes_buf() {
        use crate::async_seekable_storage::AsyncFlatData;

        let mut ram = [0u8; 64];
        let mut plane =
            AsyncCipherPlane::<_, _, 2048>::new(RamBackend::new(&mut ram), PatternCipher);
        block_on(async {
            let mut buf = [0xAAu8; 16];
            assert_eq!(
                AsyncFlatData::read_at(&mut plane, 60, &mut buf).await,
                Err(StorageError::OutOfBounds)
            );
            assert!(buf.iter().all(|&x| x == 0));
        });
    }
}
