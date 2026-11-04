//! Counter-mode composition: a 128-bit big-endian counter, any 16-byte block
//! cipher.
//!
//! [`AesCtr`] turns a [`BlockCipher16`] into an offset-addressed
//! [`StreamCipher`]. The counter block for absolute byte offset `off` is
//!
//! ```text
//! nonce[0..8] || BE64(off / 16)
//! ```
//!
//! so the high half of the counter is a caller-supplied nonce that is **never
//! modified**, and the low half is the block index inside the image. The
//! increment walks the whole 128-bit word big-endian, so in practice only
//! bytes `[8..16]` ever change (a carry into the nonce would need 2⁶⁴ blocks
//! in one image). There is no sector/IV-unit semantics and no alignment
//! requirement: an unaligned call encrypts the partial head/tail blocks
//! directly and runs the aligned middle through
//! [`CtrAccel::ctr_xor_aligned`].
//!
//! # Malleability
//!
//! CTR is a stream cipher: the ciphertext is the plaintext XORed with a
//! keystream, so an attacker who can read and write the image can flip chosen
//! plaintext bits. There is no authentication tag and no integrity check here;
//! see the [module docs](super) for the full warning.
//!
//! # Keys and counters
//!
//! Never reuse a `(key, nonce)` pair across images: the keystream would repeat
//! and XORing two images together would reveal both plaintexts. The counter
//! space of a single image is `2⁶⁴` blocks (2⁶⁸ bytes); an image must stay
//! well below that so the counter never carries into the nonce.

use super::{CipherError, StreamCipher};

/// 16-byte block cipher (single-block encryption only).
///
/// Implement this to plug a hardware or software block cipher into
/// [`AesCtr`]. Batch/accelerated implementations should also implement
/// [`CtrAccel`].
pub trait BlockCipher16 {
    /// Encrypt one block in place.
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError>;
}

/// Optional accelerated CTR core.
///
/// The default methods are fully functional; an implementation with a wider
/// primitive (AES-NI, a DMA engine, a CRYPTO peripheral) overrides
/// [`Self::ctr_xor_aligned`]. Both hooks require `buf.len() % 16 == 0` and an
/// empty buffer is a no-op.
pub trait CtrAccel: BlockCipher16 {
    /// XOR the CTR keystream into `buf.len() % 16 == 0` bytes.
    ///
    /// `counter` is the whole 128-bit counter block fed to the cipher for the
    /// **first** block; it is incremented big-endian (whole 128-bit word)
    /// after each block. The default forwards to [`Self::ctr_xor_blocks`].
    fn ctr_xor_aligned(&mut self, counter: [u8; 16], buf: &mut [u8]) -> Result<(), CipherError> {
        self.ctr_xor_blocks(counter, buf)
    }

    /// Default body: per-block [`BlockCipher16::encrypt_block`] + XOR +
    /// big-endian increment.
    ///
    /// Each keystream block is computed before it is applied, so a failing
    /// cipher never emits a half-XORed block. A backend that fails part-way
    /// through a buffer can still leave the earlier, fully processed blocks
    /// XORed; callers that need transactional behaviour use the
    /// [`CipherPlane`](super::CipherPlane) wrappers, which zero the buffer on
    /// error.
    fn ctr_xor_blocks(&mut self, counter: [u8; 16], buf: &mut [u8]) -> Result<(), CipherError> {
        if !buf.len().is_multiple_of(16) {
            return Err(CipherError::BadParameters);
        }
        let mut counter = counter;
        for chunk in buf.chunks_exact_mut(16) {
            let mut keystream = counter;
            self.encrypt_block(&mut keystream)?;
            for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
                *b ^= *k;
            }
            increment_be(&mut counter);
        }
        Ok(())
    }
}

/// Add one to a 128-bit big-endian counter.
fn increment_be(counter: &mut [u8; 16]) {
    for b in counter.iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            return;
        }
    }
}

/// Counter block for absolute byte offset `off`: `nonce[0..8] || BE64(off/16)`.
fn counter_block(nonce: [u8; 8], off: u64) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&nonce);
    block[8..].copy_from_slice(&(off / 16).to_be_bytes());
    block
}

/// CTR-mode [`StreamCipher`] over any [`CtrAccel`] block cipher.
///
/// The cipher is kept for hardware state (AES-NI key schedule, a DMA handle);
/// the nonce supplies the non-changing high half of the counter.
pub struct AesCtr<C: CtrAccel> {
    cipher: C,
    nonce: [u8; 8],
}

impl<C: CtrAccel> AesCtr<C> {
    /// Build the CTR stream from `cipher`, with `nonce` as the fixed counter
    /// prefix.
    pub fn new(cipher: C, nonce: [u8; 8]) -> Self {
        Self { cipher, nonce }
    }
}

impl<C: CtrAccel> super::NonceCipher for AesCtr<C> {
    fn set_nonce(&mut self, nonce: [u8; 8]) {
        self.nonce = nonce;
    }
}

impl<C: CtrAccel> StreamCipher for AesCtr<C> {
    fn xor(&mut self, off: u64, buf: &mut [u8]) -> Result<(), CipherError> {
        // Reject an overflowing range before touching `buf`: a wrapped cursor
        // would re-use the block-0 keystream.
        off.checked_add(buf.len() as u64)
            .ok_or(CipherError::BadParameters)?;

        let mut pos = 0;
        let mut cur = off;

        // Unaligned head: XOR only the bytes of block `off / 16` that the
        // caller asked for.
        let skip = (cur % 16) as usize;
        if skip != 0 {
            let n = core::cmp::min(16 - skip, buf.len());
            let mut keystream = counter_block(self.nonce, cur);
            self.cipher.encrypt_block(&mut keystream)?;
            for i in 0..n {
                buf[i] ^= keystream[skip + i];
            }
            pos += n;
            cur = cur.wrapping_add(n as u64);
        }

        // Aligned middle: one accelerated batch.
        let aligned = (buf.len() - pos) & !15;
        if aligned != 0 {
            let keystream = counter_block(self.nonce, cur);
            self.cipher
                .ctr_xor_aligned(keystream, &mut buf[pos..pos + aligned])?;
            pos += aligned;
            cur = cur.wrapping_add(aligned as u64);
        }

        // Trailing partial block.
        if pos < buf.len() {
            let n = buf.len() - pos;
            let mut keystream = counter_block(self.nonce, cur);
            self.cipher.encrypt_block(&mut keystream)?;
            for i in 0..n {
                buf[pos + i] ^= keystream[i];
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stateless toy block cipher: output depends only on the input block, so
    /// it is usable for split/offset consistency checks.
    struct ToyBlock;

    impl BlockCipher16 for ToyBlock {
        fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
            for (i, b) in block.iter_mut().enumerate() {
                *b = (*b).wrapping_mul(31).wrapping_add(i as u8).rotate_left(3) ^ 0x5A;
            }
            Ok(())
        }
    }

    impl CtrAccel for ToyBlock {}

    /// Identity block cipher: `encrypt_block` leaves its input untouched, so
    /// XORing a zero buffer with CTR exposes the raw counter blocks.
    struct IdentityBlock;

    impl BlockCipher16 for IdentityBlock {
        fn encrypt_block(&mut self, _block: &mut [u8; 16]) -> Result<(), CipherError> {
            Ok(())
        }
    }

    impl CtrAccel for IdentityBlock {}

    #[test]
    fn ctr_counter_layout_preserves_nonce() {
        let nonce = [0xFFu8; 8];
        let mut ctr = AesCtr::new(IdentityBlock, nonce);

        // Block 0 at offset 0.
        let mut buf = [0u8; 16];
        ctr.xor(0, &mut buf).unwrap();
        assert_eq!(&buf[..8], &nonce);
        assert_eq!(&buf[8..], &0u64.to_be_bytes());

        // Block 1 at offset 16.
        let mut buf = [0u8; 16];
        ctr.xor(16, &mut buf).unwrap();
        assert_eq!(&buf[..8], &nonce);
        assert_eq!(&buf[8..], &1u64.to_be_bytes());

        // A 4096-byte run touches blocks 0..=255 and never a nonce byte.
        let mut buf = [0u8; 4096];
        ctr.xor(0, &mut buf).unwrap();
        for i in 0..256u64 {
            assert_eq!(
                &buf[(i as usize) * 16..(i as usize) * 16 + 8],
                &nonce,
                "nonce changed at block {i}"
            );
            assert_eq!(
                &buf[(i as usize) * 16 + 8..(i as usize) * 16 + 16],
                &i.to_be_bytes(),
                "wrong block index at block {i}"
            );
        }

        // Unaligned start: the tail of block 0 then the head of block 1.
        let mut buf = [0u8; 27];
        ctr.xor(5, &mut buf).unwrap();
        // Block 0 bytes 5..16: nonce bytes 5..8 then the zero counter tail.
        assert_eq!(&buf[..3], &[0xFF; 3]);
        assert_eq!(&buf[3..11], &[0u8; 8]);
        // Block 1: the nonce again, then block index 1.
        assert_eq!(&buf[11..19], &nonce);
        assert_eq!(&buf[19..27], &1u64.to_be_bytes());
    }

    #[test]
    fn ctr_empty_buffer_is_noop() {
        let mut ctr = AesCtr::new(ToyBlock, [1u8; 8]);
        assert_eq!(ctr.xor(1234, &mut []), Ok(()));
    }

    #[test]
    fn ctr_split_consistency_and_double_xor() {
        let mut one_shot = [0u8; 64];
        for (i, b) in one_shot.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plain = one_shot;

        let mut ctr = AesCtr::new(ToyBlock, [0x42u8; 8]);
        ctr.xor(3, &mut one_shot).unwrap();

        // Same range, split at every awkward boundary (including inside a
        // block and across the aligned middle).
        let mut split = plain;
        let mut ctr = AesCtr::new(ToyBlock, [0x42u8; 8]);
        ctr.xor(3, &mut split[..5]).unwrap();
        ctr.xor(8, &mut split[5..23]).unwrap();
        ctr.xor(26, &mut split[23..48]).unwrap();
        ctr.xor(51, &mut split[48..]).unwrap();
        assert_eq!(one_shot, split);

        // Double XOR with the same key/nonce is the identity.
        let mut ctr = AesCtr::new(ToyBlock, [0x42u8; 8]);
        ctr.xor(3, &mut one_shot).unwrap();
        assert_eq!(one_shot, plain);
    }

    #[test]
    fn ctr_offset_and_nonce_change_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];

        AesCtr::new(ToyBlock, [0u8; 8]).xor(0, &mut a).unwrap();
        AesCtr::new(ToyBlock, [1u8; 8]).xor(0, &mut b).unwrap();
        AesCtr::new(ToyBlock, [0u8; 8]).xor(16, &mut c).unwrap();

        assert_ne!(a, b, "different nonce must change the keystream");
        assert_ne!(a, c, "different offset must change the keystream");
    }

    /// Two `CtrAccel`s over the same block cipher: one uses only the default
    /// bodies, the other batches four blocks per `ctr_xor_aligned` call.
    /// They must produce identical ciphertext.
    struct DefaultAccel;

    impl BlockCipher16 for DefaultAccel {
        fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
            ToyBlock.encrypt_block(block)
        }
    }

    impl CtrAccel for DefaultAccel {}

    struct BatchedAccel;

    impl BlockCipher16 for BatchedAccel {
        fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
            ToyBlock.encrypt_block(block)
        }
    }

    impl CtrAccel for BatchedAccel {
        fn ctr_xor_aligned(
            &mut self,
            mut counter: [u8; 16],
            buf: &mut [u8],
        ) -> Result<(), CipherError> {
            for chunk in buf.chunks_mut(64) {
                self.ctr_xor_blocks(counter, chunk)?;
                for _ in 0..chunk.len().div_ceil(16) {
                    increment_be(&mut counter);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn ctr_accel_batching_matches_default() {
        let counter = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        let plain: [u8; 256] = core::array::from_fn(|i| i as u8);

        let mut batch_a = plain;
        let mut batch_b = plain;
        DefaultAccel.ctr_xor_aligned(counter, &mut batch_a).unwrap();
        BatchedAccel.ctr_xor_aligned(counter, &mut batch_b).unwrap();
        assert_eq!(batch_a, batch_b);

        // And the batch path agrees with the plain per-block body.
        let mut blocks = plain;
        DefaultAccel.ctr_xor_blocks(counter, &mut blocks).unwrap();
        assert_eq!(batch_a, blocks);
    }

    // ── NIST SP 800-38A F.5.5 / F.5.6 (AES-256-CTR) ─────────────────

    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;

    struct Aes256Accel {
        cipher: Aes256,
    }

    impl BlockCipher16 for Aes256Accel {
        fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
            BlockEncrypt::encrypt_block(&self.cipher, block);
            Ok(())
        }
    }

    impl CtrAccel for Aes256Accel {}

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

    #[test]
    fn nist_sp800_38a_aes256_ctr_vector() {
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let counter: [u8; 16] = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plain: [u8; 64] = unhex(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let expected: [u8; 64] = unhex(
            "601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6",
        );

        // Through the raw CTR core (the whole block is the counter).
        let mut out = plain;
        let mut accel = Aes256Accel {
            cipher: Aes256::new_from_slice(&key).unwrap(),
        };
        accel.ctr_xor_blocks(counter, &mut out).unwrap();
        assert_eq!(out, expected);

        // Through `AesCtr`: the counter block is `nonce || BE64(0)`, i.e. the
        // NIST counter's high half with a zero block index. Compare against
        // the raw core fed that same block (the low half differs from the
        // NIST vector, so the ciphertext legitimately differs too).
        let mut out = plain;
        let nonce: [u8; 8] = counter[..8].try_into().unwrap();
        let mut layout_counter = [0u8; 16];
        layout_counter[..8].copy_from_slice(&nonce);
        let mut expected_layout = plain;
        Aes256Accel {
            cipher: Aes256::new_from_slice(&key).unwrap(),
        }
        .ctr_xor_blocks(layout_counter, &mut expected_layout)
        .unwrap();

        let mut ctr = AesCtr::new(
            Aes256Accel {
                cipher: Aes256::new_from_slice(&key).unwrap(),
            },
            nonce,
        );
        ctr.xor(0, &mut out).unwrap();
        assert_eq!(out, expected_layout);
        assert_ne!(out, expected);
    }

    #[test]
    fn ctr_rejects_unaligned_batch_and_offset_overflow() {
        let mut accel = Aes256Accel {
            cipher: Aes256::new_from_slice(&[0u8; 32]).unwrap(),
        };
        let mut buf = [0xAAu8; 20];
        assert_eq!(
            accel.ctr_xor_blocks([0u8; 16], &mut buf),
            Err(CipherError::BadParameters)
        );
        assert!(buf.iter().all(|&b| b == 0xAA));

        let mut ctr = AesCtr::new(ToyBlock, [0u8; 8]);
        let mut tiny = [0x5Au8; 3];
        assert_eq!(
            ctr.xor(u64::MAX, &mut tiny),
            Err(CipherError::BadParameters)
        );
        assert_eq!(tiny, [0x5Au8; 3]);

        // The default `ctr_xor_aligned` forwards to the checked body.
        let mut aligned = [0xAAu8; 20];
        assert_eq!(
            accel.ctr_xor_aligned([0u8; 16], &mut aligned),
            Err(CipherError::BadParameters)
        );
        assert!(aligned.iter().all(|&b| b == 0xAA));
    }

    /// The partial head/tail arithmetic is exercised against a real AES-256,
    /// with the expected keystream bytes precomputed externally: the counter
    /// block is `f0f1f2f3f4f5f6f7 || BE64(n)` and the buffer starts at byte 3
    /// (or 15) of block 0.
    #[test]
    fn ctr_unaligned_offset_matches_reference() {
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let nonce: [u8; 8] = unhex("f0f1f2f3f4f5f6f7");

        let at3: [u8; 32] =
            unhex("4fbf3694c871e1d290c5ba13a7125f28bc6d2414dde799a2f216cf5f827aefda");
        let at15: [u8; 32] =
            unhex("a7125f28bc6d2414dde799a2f216cf5f827aefdadd04ce861a9ef718138d77f3");

        for (off, expected) in [(3u64, at3), (15u64, at15)] {
            let mut buf = [0u8; 32];
            let mut ctr = AesCtr::new(
                Aes256Accel {
                    cipher: Aes256::new_from_slice(&key).unwrap(),
                },
                nonce,
            );
            ctr.xor(off, &mut buf).unwrap();
            assert_eq!(buf, expected, "offset {off}");

            // Split inside the head block and again inside the aligned middle.
            let mut split = [0u8; 32];
            let mut ctr = AesCtr::new(
                Aes256Accel {
                    cipher: Aes256::new_from_slice(&key).unwrap(),
                },
                nonce,
            );
            ctr.xor(off, &mut split[..5]).unwrap();
            ctr.xor(off + 5, &mut split[5..17]).unwrap();
            ctr.xor(off + 17, &mut split[17..]).unwrap();
            assert_eq!(split, expected, "split offset {off}");
        }
    }
}
