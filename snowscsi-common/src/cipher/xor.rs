//! Obfuscation, not encryption: [`XorMix`] turns a key, nonce and block index
//! into a keystream with splitmix64-style mixing.
//!
//! `XorMix` is **not a cipher**. It has no cryptanalysis behind it, no
//! diffusion guarantees and no security margin; it exists to keep casual
//! inspection of an image from revealing its structure (and to exercise the
//! [`StreamCipher`] seam without a real cipher). Anyone who obtains the key
//! can read the image. Use [`ChaCha20`](super::ChaCha20) (or
//! [`AesCtr`](super::AesCtr)) when confidentiality actually matters.
//!
//! The construction is deterministic: the 32-byte key and 8-byte nonce are
//! mixed into a seed with the 64-bit block index, and each of the eight output
//! words is that seed XOR a per-word domain constant, run through five
//! splitmix64 rounds. This is not a cipher and makes no cryptographic
//! separation claim; it only keeps different offsets from repeating the same
//! visible pattern.

use super::{CipherError, CipherKey, StreamCipher};

/// Splitmix64's 64-bit avalanche function.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Five mixing rounds per output word.
fn mix5(z: u64) -> u64 {
    let mut z = z;
    for _ in 0..5 {
        z = splitmix64(z);
    }
    z
}

/// Obfuscation-only [`StreamCipher`] (see the [module docs](self)).
pub struct XorMix {
    key: [u8; 32],
    nonce: [u8; 8],
}

impl XorMix {
    /// Build the mixer from a 256-bit key and a 64-bit nonce.
    pub fn new(key: &CipherKey, nonce: [u8; 8]) -> Self {
        Self {
            key: *key.as_bytes(),
            nonce,
        }
    }

    /// 64-byte keystream block for `index`.
    fn keystream_block(&self, index: u64) -> [u8; 64] {
        let mut words = [0u64; 4];
        for (word, chunk) in words.iter_mut().zip(self.key.chunks_exact(8)) {
            *word = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }
        let nonce = u64::from_le_bytes(self.nonce);
        // Mix key words, nonce and block index into the seed. This is not a
        // cryptographic domain-separation claim: `XorMix` is explicitly an
        // obfuscator, not a cipher.
        let seed = words[0]
            ^ words[1].rotate_left(17)
            ^ words[2].rotate_left(33)
            ^ words[3].rotate_left(49)
            ^ nonce.rotate_left(23)
            ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15);

        let mut out = [0u8; 64];
        for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
            let word = mix5(seed ^ (i as u64 + 1).wrapping_mul(0xA076_1D64_78BD_642F));
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl StreamCipher for XorMix {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> CipherKey {
        CipherKey::from_bytes(&[0x3Cu8; 32]).unwrap()
    }

    #[test]
    fn round_trip_and_determinism() {
        let mut buf = [0u8; 100];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plain = buf;

        XorMix::new(&key(), [7u8; 8]).xor(13, &mut buf).unwrap();
        assert_ne!(buf, plain);

        // A second, independent mixer with the same parameters decrypts it.
        XorMix::new(&key(), [7u8; 8]).xor(13, &mut buf).unwrap();
        assert_eq!(buf, plain);

        // And the ciphertext itself is reproducible.
        let mut a = plain;
        let mut b = plain;
        XorMix::new(&key(), [7u8; 8]).xor(13, &mut a).unwrap();
        XorMix::new(&key(), [7u8; 8]).xor(13, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn offset_and_nonce_change_output() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut c = [0u8; 64];
        XorMix::new(&key(), [0u8; 8]).xor(0, &mut a).unwrap();
        XorMix::new(&key(), [1u8; 8]).xor(0, &mut b).unwrap();
        XorMix::new(&key(), [0u8; 8]).xor(64, &mut c).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.iter().any(|&x| x != 0));
    }

    #[test]
    fn split_consistency() {
        let mut one_shot = [0u8; 160];
        let plain = one_shot;
        XorMix::new(&key(), [9u8; 8]).xor(5, &mut one_shot).unwrap();

        let mut split = plain;
        let mut mixer = XorMix::new(&key(), [9u8; 8]);
        mixer.xor(5, &mut split[..3]).unwrap();
        mixer.xor(8, &mut split[3..70]).unwrap();
        mixer.xor(75, &mut split[70..]).unwrap();
        assert_eq!(one_shot, split);
    }
}
