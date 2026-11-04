//! Original DJB ChaCha stream cipher.
//!
//! This is **Bernstein's original ChaCha**, not the RFC 8439 (IETF) variant:
//! a 256-bit key, a **64-bit nonce**, a 64-bit block counter and 64-byte
//! blocks. The state is
//!
//! ```text
//! "expand 32-byte k" (4 words)
//! key[0..32]         (8 little-endian words)
//! block index        (2 little-endian words, words 12/13)
//! nonce[0..8]        (2 little-endian words, words 14/15)
//! ```
//!
//! and the output is the 16 working words plus the 16 input words, written
//! little-endian. [`ChaCha20`] is the full 20-round cipher; [`ChaCha8`] and
//! [`ChaCha12`] trade margin for speed. No lookup tables (no cache-timing
//! tables), no allocation and no `std`.
//!
//! Like every stream cipher here, ChaCha is malleable and provides no
//! integrity; see the [module docs](super) for the key/nonce-reuse warning.

use super::{CipherError, CipherKey, StreamCipher};

/// ChaCha constants: `"expand 32-byte k"` read as little-endian words.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Original DJB ChaCha with `ROUNDS` rounds.
///
/// The round count is restricted to the three deployed variants: [`ChaCha8`],
/// [`ChaCha12`] and [`ChaCha20`]. Any other value makes [`ChaCha::new`] return
/// [`CipherError::BadParameters`], so a manifest or policy cannot silently
/// select an unreviewed (or accidentally odd) round count.
pub struct ChaCha<const ROUNDS: usize> {
    key: [u8; 32],
    nonce: [u8; 8],
}

/// ChaCha with 8 rounds.
pub type ChaCha8 = ChaCha<8>;
/// ChaCha with 12 rounds.
pub type ChaCha12 = ChaCha<12>;
/// ChaCha with 20 rounds (the standard cipher).
pub type ChaCha20 = ChaCha<20>;

impl<const ROUNDS: usize> ChaCha<ROUNDS> {
    /// Build the cipher from a 256-bit key and a 64-bit nonce.
    ///
    /// # Errors
    ///
    /// [`CipherError::BadParameters`] unless `ROUNDS` is `8`, `12` or `20`.
    /// The nonce is not validated: any 64-bit value is a legal nonce, but a
    /// caller must never reuse one with the same key.
    pub fn new(key: &CipherKey, nonce: [u8; 8]) -> Result<Self, CipherError> {
        if !matches!(ROUNDS, 8 | 12 | 20) {
            return Err(CipherError::BadParameters);
        }
        Ok(Self {
            key: *key.as_bytes(),
            nonce,
        })
    }

    /// Expand the state and run `ROUNDS` rounds, returning the 64-byte
    /// keystream for `index`.
    fn keystream_block(&self, index: u64) -> [u8; 64] {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&SIGMA);
        for (word, chunk) in state[4..12].iter_mut().zip(self.key.chunks_exact(4)) {
            *word = le_word(chunk);
        }
        state[12] = index as u32;
        state[13] = (index >> 32) as u32;
        state[14] = le_word(&self.nonce[..4]);
        state[15] = le_word(&self.nonce[4..]);

        let mut work = state;
        for _ in 0..ROUNDS / 2 {
            double_round(&mut work);
        }

        let mut out = [0u8; 64];
        for (chunk, (w, s)) in out.chunks_exact_mut(4).zip(work.iter().zip(state.iter())) {
            chunk.copy_from_slice(&w.wrapping_add(*s).to_le_bytes());
        }
        out
    }
}

impl<const ROUNDS: usize> super::NonceCipher for ChaCha<ROUNDS> {
    fn set_nonce(&mut self, nonce: [u8; 8]) {
        self.nonce = nonce;
    }
}

impl<const ROUNDS: usize> StreamCipher for ChaCha<ROUNDS> {
    fn xor(&mut self, off: u64, buf: &mut [u8]) -> Result<(), CipherError> {
        let mut block = off / 64;
        let mut skip = (off % 64) as usize;
        let mut pos = 0;
        while pos < buf.len() {
            let keystream = self.keystream_block(block);
            let n = core::cmp::min(64 - skip, buf.len() - pos);
            for i in 0..n {
                buf[pos + i] ^= keystream[skip + i];
            }
            pos += n;
            skip = 0;
            block = block.wrapping_add(1);
        }
        Ok(())
    }
}

/// Read four bytes as a little-endian word.
fn le_word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// One ChaCha quarter-round on the state indices `a, b, c, d`.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// One ChaCha double round: four column rounds then four diagonal rounds.
fn double_round(state: &mut [u32; 16]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn keystream<const ROUNDS: usize>(key: &[u8; 32], nonce: [u8; 8]) -> [u8; 64] {
        let mut cipher =
            ChaCha::<ROUNDS>::new(&CipherKey::from_bytes(key).unwrap(), nonce).unwrap();
        let mut out = [0u8; 64];
        cipher.xor(0, &mut out).unwrap();
        out
    }

    /// The famous original-ChaCha test vector. Note that it uses an **all-zero
    /// key**, not the sequential key: the 64-byte keystream of `76b8e0ad…`
    /// belongs to the ECRYPT "Set key: 00…00 / Set IV: 00…00" vector.
    #[test]
    fn djb_chacha20_zero_key_vector() {
        let expected: [u8; 64] = unhex(
            "76b8e0ada0f13d90405d6ae55386bd28\
             bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a37\
             6a43b8f41518a11cc387b669b2ee6586",
        );
        assert_eq!(keystream::<20>(&[0u8; 32], [0u8; 8]), expected);
    }

    /// Same construction with the sequential key `00 01 .. 1f` (also a DJB
    /// known-answer vector; the keystream differs from the zero-key one).
    #[test]
    fn djb_chacha20_sequential_key_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let expected: [u8; 64] = unhex(
            "39fd2b7dd9c5196a8dbd0377b8dc4a49\
             8a35d86fbcde6accb2cc7d4cd8ea2492\
             2b23cce7a26023ab3f0eef693ac87f64\
             258235eab1f7a32dc22762a0485b410c",
        );
        assert_eq!(keystream::<20>(&key, [0u8; 8]), expected);
    }

    /// **Regression constant, not a standard vector**: ChaCha8's 64-byte
    /// keystream for the sequential key / zero nonce, generated once from this
    /// implementation to lock the round schedule.
    #[test]
    fn chacha8_regression_constant() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let expected: [u8; 64] = unhex(
            "4015b28f6e12ab6ad9e8667b31c51233\
             f78f172790b2d94f326b2ed7ffbcbecb\
             ff9ead365f89ce3b6f4055bc759d90fd\
             8f831d27c7b0df93b3b9ed8238a256d6",
        );
        assert_eq!(keystream::<8>(&key, [0u8; 8]), expected);
    }

    /// **Regression constant, not a standard vector**: ChaCha12's 64-byte
    /// keystream for the sequential key / zero nonce.
    #[test]
    fn chacha12_regression_constant() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let expected: [u8; 64] = unhex(
            "f231f9ffd17ac65e4405f325d7e940aa\
             4913601fc2be46bce9c3cac3d91a1a36\
             5940b308c2857c9f29d6e2548528d49a\
             612b1b0ae6765d16e585aefb46368879",
        );
        assert_eq!(keystream::<12>(&key, [0u8; 8]), expected);
    }

    #[test]
    fn offset_split_consistency() {
        let key = CipherKey::from_bytes(&[0x5Au8; 32]).unwrap();
        let mut one_shot = [0u8; 200];
        for (i, b) in one_shot.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plain = one_shot;

        // Start inside a block (off % 64 == 13), then split across several
        // block boundaries.
        let mut cipher = ChaCha20::new(&key, [9u8; 8]).unwrap();
        cipher.xor(77, &mut one_shot).unwrap();

        let mut split = plain;
        let mut cipher = ChaCha20::new(&key, [9u8; 8]).unwrap();
        cipher.xor(77, &mut split[..20]).unwrap();
        cipher.xor(97, &mut split[20..64]).unwrap();
        cipher.xor(141, &mut split[64..199]).unwrap();
        cipher.xor(276, &mut split[199..]).unwrap();
        assert_eq!(one_shot, split);
    }

    #[test]
    fn double_xor_is_identity() {
        let key = CipherKey::from_bytes(&[1u8; 32]).unwrap();
        let mut buf = [0u8; 128];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let plain = buf;
        let mut cipher = ChaCha20::new(&key, [2u8; 8]).unwrap();
        cipher.xor(3, &mut buf).unwrap();
        assert_ne!(buf, plain);
        cipher.xor(3, &mut buf).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn nonce_and_offset_change_output() {
        let key = CipherKey::from_bytes(&[1u8; 32]).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut c = [0u8; 64];
        ChaCha20::new(&key, [0u8; 8])
            .unwrap()
            .xor(0, &mut a)
            .unwrap();
        ChaCha20::new(&key, [1u8; 8])
            .unwrap()
            .xor(0, &mut b)
            .unwrap();
        ChaCha20::new(&key, [0u8; 8])
            .unwrap()
            .xor(64, &mut c)
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn invalid_round_counts_are_rejected() {
        let key = CipherKey::from_bytes(&[0u8; 32]).unwrap();
        for rounds in [0usize, 4, 6, 7, 10, 16, 24] {
            let rejected = match rounds {
                0 => ChaCha::<0>::new(&key, [0u8; 8]).err(),
                4 => ChaCha::<4>::new(&key, [0u8; 8]).err(),
                6 => ChaCha::<6>::new(&key, [0u8; 8]).err(),
                7 => ChaCha::<7>::new(&key, [0u8; 8]).err(),
                10 => ChaCha::<10>::new(&key, [0u8; 8]).err(),
                16 => ChaCha::<16>::new(&key, [0u8; 8]).err(),
                24 => ChaCha::<24>::new(&key, [0u8; 8]).err(),
                _ => unreachable!(),
            };
            assert_eq!(rejected, Some(CipherError::BadParameters), "{rounds}");
        }
        assert!(ChaCha::<8>::new(&key, [0u8; 8]).is_ok());
        assert!(ChaCha::<12>::new(&key, [0u8; 8]).is_ok());
        assert!(ChaCha::<20>::new(&key, [0u8; 8]).is_ok());
    }

    /// Pins the 64-bit counter split (words 12/13) and the nonce word order
    /// (words 14/15): asymmetric nonce `01..08`, block index 3, byte offset 5
    /// inside that block. The expected bytes are the block-3 keystream from
    /// byte 5 followed by block 4, precomputed externally.
    #[test]
    fn chacha_counter_and_nonce_word_order() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let expected: [u8; 64] = unhex(
            "88ff1e22f9826eba4904cd36f5e48e42\
             d69fda7a6b398d5a58cd1efac05729ea\
             293e62e4ec763c132435f51354a49a80\
             904488dd9316a97dc2f6615bf37cf0f8",
        );
        let mut out = [0u8; 64];
        ChaCha20::new(&CipherKey::from_bytes(&key).unwrap(), nonce)
            .unwrap()
            .xor(3 * 64 + 5, &mut out)
            .unwrap();
        assert_eq!(out, expected);
    }
}
