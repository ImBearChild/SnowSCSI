//! Password-based key derivation: the [`Kdf`] seam and a dependency-free
//! PBKDF2-HMAC-SHA256 implementation.
//!
//! A password is not a key. It has low entropy, it is reused across systems and
//! it is guessable. PBKDF2 (RFC 8018) stretches it with a **public** salt and
//! many HMAC (RFC 2104) rounds so that each offline guess costs that work: an
//! attacker who steals the image still has to run the derivation per candidate
//! password.
//!
//! # What this cannot do
//!
//! PBKDF2 only slows **offline guessing**. A weak password remains weak: a
//! dictionary word, a short password or one of the billion leaked passwords is
//! recovered at the same cost as any other guess. The salt is **public** — it
//! only stops precomputation and makes the same password derive different keys
//! on different images, so it must be stored next to the image, not kept
//! secret. The iteration count is a **policy decision**: this library accepts
//! any value `>= 1` and has no upper bound, so the caller must pick a count
//! that is slow enough for an attacker (and fast enough for the device), and
//! must not accept an attacker-controlled count without bounding it.
//!
//! # Unaudited software crypto
//!
//! This is an in-crate, allocation-free, `unsafe`-free, `no_std` implementation
//! written for portability and reviewability, **not** an audited cryptographic
//! library. There is no protection against side channels beyond the constant
//! structure of SHA-256 itself: the code has no secret-dependent branches and
//! no lookup tables indexed by secret data (the SHA-256 round constants are
//! indexed by the round number only). It has not been reviewed by cryptographers
//! and has not been hardened against power, EM or fault attacks.
//!
//! # No allocation, streaming input
//!
//! Everything is fixed-size stack state. The salt is **streamed** into the HMAC
//! inner hash instead of being copied into a buffer, so a salt of any length
//! works (there is no truncation and no rejection). The password is only read;
//! when it is longer than one HMAC block (64 bytes) it is hashed first, as the
//! HMAC key-normalisation step requires.
//!
//! Stack use peaks in the compression function: 256 bytes of message schedule
//! plus the working words and the two 112-byte hash states of the HMAC
//! context. A whole derivation stays **well under 2 KiB** of stack.
//!
//! # Best-effort scrubbing, not zeroize
//!
//! [`SoftKdf::derive`] and [`pbkdf2_hmac_sha256`] overwrite their local `U`,
//! `T` and pad/key state with zeros before returning and pass the buffers
//! through [`core::hint::black_box`] so the compiler cannot elide the writes.
//! This is **not** a real zeroize: there is no dependency, no `Drop` guard (an
//! early return or a panic skips it), copies may already exist in registers,
//! the stack may be swapped out, and the caller's password and salt buffers are
//! untouched. Do not treat it as a memory-security guarantee.

use super::CipherError;

/// Password -> 256-bit key derivation seam.
pub trait Kdf {
    /// Derive a 32-byte key from `password` and `salt` with `iterations`
    /// rounds. `iterations` must be >= 1; policy limits are a caller concern.
    ///
    /// # Errors
    ///
    /// `iterations == 0` returns [`CipherError::BadParameters`] and leaves
    /// `out` untouched.
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8; 32],
    ) -> Result<(), CipherError>;
}

/// Software PBKDF2-HMAC-SHA256. `no_std`, no allocation, no `unsafe`.
///
/// A zero-sized unit struct: all state is local to each [`Kdf::derive`] call,
/// so one value can be shared or recreated freely.
#[derive(Clone, Copy, Debug, Default)]
pub struct SoftKdf;

impl Kdf for SoftKdf {
    fn derive(
        &mut self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8; 32],
    ) -> Result<(), CipherError> {
        pbkdf2_hmac_sha256(password, salt, iterations, out)
    }
}

/// PBKDF2-HMAC-SHA256, 32-byte output.
///
/// Implements RFC 8018 with `dkLen = 32`, i.e. exactly one output block (`T_1`):
///
/// ```text
/// U_1 = HMAC-SHA256(P, S || INT(1))
/// U_i = HMAC-SHA256(P, U_{i-1})
/// T_1 = U_1 xor U_2 xor ... xor U_c
/// ```
///
/// `INT(1)` is the 4-byte big-endian block index. The salt is streamed into
/// the inner hash, so there is no dedicated salt buffer, no length limit and
/// no truncation.
///
/// # Errors
///
/// [`CipherError::BadParameters`] when `iterations == 0` (there is no
/// derivation without at least one round); `out` is left untouched.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8; 32],
) -> Result<(), CipherError> {
    if iterations == 0 {
        return Err(CipherError::BadParameters);
    }

    // The keyed pad states are computed once; every round clones them, so the
    // password is hashed (when longer than a block) only once.
    let mut template = HmacSha256::new(password);

    // U_1 = HMAC(P, S || INT(1)); streaming the salt keeps any length working.
    let mut u = {
        let mut mac = template.clone();
        mac.update(salt);
        mac.update(&1u32.to_be_bytes());
        mac.finalize()
    };
    let mut t = u;

    // U_i = HMAC(P, U_{i-1}); T = U_1 xor ... xor U_c.
    for _ in 1..iterations {
        let mut mac = template.clone();
        mac.update(&u);
        u = mac.finalize();
        for (acc, byte) in t.iter_mut().zip(u.iter()) {
            *acc ^= *byte;
        }
    }

    out.copy_from_slice(&t);

    wipe(&mut u);
    wipe(&mut t);
    template.clear();
    Ok(())
}

/// SHA-256 (crate-internal unless a caller needs it).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize()
}

/// HMAC-SHA256 (crate-internal).
///
/// PBKDF2 uses the keyed-prefix [`HmacSha256`] state directly (to avoid
/// re-processing the pads per round), so this one-shot form is used by the
/// keyslot module and the unit tests. It stays crate-internal rather than
/// becoming part of the public API.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(data);
    mac.finalize()
}

/// Keyed HMAC-SHA256 state.
///
/// The two hash states already contain the ipad/opad block, so a round only
/// feeds the message and finalises; cloning the template is how PBKDF2 reuses
/// the keyed prefix without re-processing the password or the pads. Cloning also
/// copies the key-derived state, which is why the template is cleared explicitly
/// after the derivation loop.
#[derive(Clone)]
struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        // K0 = key padded to one block; a longer key is hashed first (FIPS 198-1).
        let mut k0 = [0u8; 64];
        if key.len() > 64 {
            let mut digest = sha256(key);
            k0[..32].copy_from_slice(&digest);
            wipe(&mut digest);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for ((ip, op), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(k0.iter()) {
            *ip ^= *k;
            *op ^= *k;
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);

        wipe(&mut k0);
        wipe(&mut ipad);
        wipe(&mut opad);
        Self { inner, outer }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let mut inner = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&inner);
        wipe(&mut inner);
        outer.finalize()
    }

    /// Zero the keyed pad states.
    fn clear(&mut self) {
        self.inner.clear();
        self.outer.clear();
    }
}

/// Zero a buffer as far as the compiler is concerned.
///
/// `black_box` makes the pointer escape, so the zeroing stores cannot be
/// removed as dead. This is hygiene, not a memory-security primitive; see the
/// [module docs](self).
fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    core::hint::black_box(buf);
}

/// SHA-256 round constants (FIPS 180-4 §4.2.2). Indexed by round number only.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Streaming SHA-256 (FIPS 180-4).
///
/// The buffer never holds a complete block after [`Self::update`] returns, so
/// `buf_len < 64` is an invariant used by [`Self::finalize`]. Branches depend on
/// lengths, never on message bytes; there are no data-indexed tables. The
/// compression function needs 256 bytes of message schedule, which is the
/// largest local in this module.
#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = core::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            compress(&mut self.state, block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Append 0x80, then zeros, then the 64-bit big-endian bit length.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..].fill(0);
            compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buf);

        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        self.clear();
        out
    }

    /// Zero the hash state and buffered message bytes.
    fn clear(&mut self) {
        wipe(&mut self.buf);
        self.state.fill(0);
        core::hint::black_box(&self.state);
        self.buf_len = 0;
        self.total_len = 0;
    }
}

/// One SHA-256 compression function call on a 64-byte block.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for (round, k) in K.iter().enumerate() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(w[round]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);

    // The schedule holds message-derived words (for an HMAC pad block that
    // includes key material), so scrub it on the way out.
    w.fill(0);
    core::hint::black_box(&mut w);
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn derive(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut out).unwrap();
        out
    }

    // ── SHA-256, FIPS 180-4 examples ────────────────────────────────

    #[test]
    fn sha256_fips_examples() {
        assert_eq!(
            sha256(b""),
            unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    /// FIPS 180-4's 1,000,000 × `'a'` example. Streams the input in 1000-byte
    /// chunks so the test itself needs no allocation.
    #[test]
    fn sha256_million_a() {
        let chunk = [b'a'; 1000];
        let mut hash = Sha256::new();
        for _ in 0..1000 {
            hash.update(&chunk);
        }
        assert_eq!(
            hash.finalize(),
            unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    // ── HMAC-SHA256, RFC 4231 cases 1, 2, 3, 4, 6, 7 ────────────────

    #[test]
    fn hmac_sha256_rfc4231() {
        // Case 1: 20-byte key, short ASCII data.
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // Case 2: a key shorter than the block size ("Jefe").
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // Case 3: 20 × 0xaa key, 50 × 0xdd data.
        assert_eq!(
            hmac_sha256(&[0xaa; 20], &[0xdd; 50]),
            unhex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
        );
        // Case 4: 25-byte sequential key.
        let key: [u8; 25] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(
            hmac_sha256(&key, &[0xcd; 50]),
            unhex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
        );
        // Case 6: 131-byte key, i.e. longer than the 64-byte block size, so
        // HMAC must hash it first.
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
        // Case 7: long key *and* long data.
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size \
                  data. The key needs to be hashed before being used by the HMAC algorithm."
            ),
            unhex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
        );
    }

    /// Exactly one HMAC block (64 bytes) needs no hashing and no padding.
    /// Regression constant cross-checked with Python `hmac`/`hashlib`; there is
    /// no RFC 4231 case at this boundary.
    #[test]
    fn hmac_sha256_exactly_one_block_key() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hmac_sha256(&key, b"SnowSCSI HMAC 64-byte key"),
            unhex("5b54cb6a698e746db968aae44e7e9e930b18f233fee70943b7a6ec34e22251d7")
        );
    }

    // ── PBKDF2-HMAC-SHA256, RFC 7914 §11 ────────────────────────────

    /// RFC 7914 §11 (`passwd` / `salt`, c=1). Only the first 32 bytes of the
    /// published 64-byte output are compared.
    #[test]
    fn pbkdf2_rfc7914_c1() {
        assert_eq!(
            derive(b"passwd", b"salt", 1),
            unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
        );
    }

    /// RFC 7914 §11 (`Password` / `NaCl`, c=80000). Compared against the first
    /// 32 bytes of the published 64-byte output.
    #[test]
    fn pbkdf2_rfc7914_c80000() {
        assert_eq!(
            derive(b"Password", b"NaCl", 80_000),
            unhex("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56")
        );
    }

    /// **Regression constant, not an RFC vector**: RFC 7914 §11 only publishes
    /// the two vectors above. This value for `passwd` / `salt` / c=80000 was
    /// produced independently with Python's `hashlib.pbkdf2_hmac` (OpenSSL) and
    /// is locked here to cover a second password/salt pair at a real-world
    /// iteration count.
    #[test]
    fn pbkdf2_passwd_salt_c80000_regression() {
        assert_eq!(
            derive(b"passwd", b"salt", 80_000),
            unhex("f5425a9368edddad5cf28116d61d66a3a7b69d63e204f6eadbc0a38ed87e35e6")
        );
    }

    /// **Regression constant, not an RFC vector**: `passwd` / `salt`,
    /// c=2,000,000, cross-checked against Python's `hashlib.pbkdf2_hmac`
    /// (OpenSSL). Ignored because it takes several seconds in a debug build;
    /// run with `--ignored` to exercise the long loop.
    #[test]
    #[ignore = "2,000,000 rounds is too slow for the default test run"]
    fn pbkdf2_c2000000_regression() {
        assert_eq!(
            derive(b"passwd", b"salt", 2_000_000),
            unhex("031916499563f5b8f79e78dfc2098599031adcef7b6b9470234e2c7e663babbc")
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn zero_iterations_is_rejected() {
        let mut out = [0xAAu8; 32];
        assert_eq!(
            pbkdf2_hmac_sha256(b"pw", b"salt", 0, &mut out),
            Err(CipherError::BadParameters)
        );
        // The output is untouched on the error path.
        assert_eq!(out, [0xAAu8; 32]);

        let mut kdf = SoftKdf;
        assert_eq!(
            kdf.derive(b"pw", b"salt", 0, &mut out),
            Err(CipherError::BadParameters)
        );
        // The seam has the same untouched-output contract.
        assert_eq!(out, [0xAAu8; 32]);
    }

    /// Salt lengths that land on SHA-256 block boundaries exercise the
    /// split-update path (a second `update` completing a buffered block) and
    /// the `finalize` padding edge (63 bytes before the length field).
    /// Regression constants cross-checked with Python `hashlib`.
    #[test]
    fn pbkdf2_salt_block_boundaries() {
        let salt59: [u8; 59] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            derive(b"passwd", &salt59, 3),
            unhex("3ea05c7ac81ef17335e44272d150f1bb467ccf89fd87968f03c3b80d97d7e13d")
        );
        let salt63: [u8; 63] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            derive(b"passwd", &salt63, 3),
            unhex("e115d8c0cc290befeaf6ee10fb7e0ebd22918685f441ed0e9ca2b5b039b93b6e")
        );
    }

    #[test]
    fn one_iteration_is_accepted() {
        // c=1 is the RFC 7914 vector above; this pins the boundary explicitly.
        assert_eq!(
            derive(b"passwd", b"salt", 1),
            unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
        );
    }

    /// **Regression constant, not an RFC vector**: empty password, `salt`,
    /// c=1, cross-checked against Python's `hashlib.pbkdf2_hmac`. Exercises the
    /// zero-length HMAC key (the whole pad block is the ipad/opad constant).
    #[test]
    fn pbkdf2_empty_password_regression() {
        assert_eq!(
            derive(b"", b"salt", 1),
            unhex("f135c27993baf98773c5cdb40a5706ce6a345cde61b000a67858650cd6a324d7")
        );
    }

    /// **Regression constant, not an RFC vector**: 72-byte password (longer
    /// than the 64-byte HMAC block, so the key is hashed first), `salt`, c=1,
    /// cross-checked against Python's `hashlib.pbkdf2_hmac`. Exercises the
    /// HMAC key-hashing path.
    #[test]
    fn pbkdf2_long_password_regression() {
        let long = *b"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassword";
        assert!(long.len() > 64);
        assert_eq!(
            derive(&long, b"salt", 1),
            unhex("adc8f9ff2eaf85aab29d5736b64707d2f5e4b05070e2d95084ba40f4b0c4c9f2")
        );
    }

    /// **Regression constant, not an RFC vector**: a 100-byte salt, `passwd`,
    /// c=1, cross-checked against Python's `hashlib.pbkdf2_hmac`. The salt is
    /// longer than any fixed buffer in this module because it is streamed into
    /// the HMAC inner hash.
    #[test]
    fn pbkdf2_long_salt_streams() {
        let salt: [u8; 100] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            derive(b"passwd", &salt, 1),
            unhex("310a1a70aed1935e921160137a59e6b438e9ab2d045f47f1a35d2a09a71061e5")
        );
    }

    /// [`SoftKdf`] is a thin wrapper: both entry points must agree.
    #[test]
    #[allow(clippy::default_constructed_unit_structs)] // `Default` is part of the API.
    fn soft_kdf_matches_free_function() {
        let mut kdf = SoftKdf::default();
        let mut trait_out = [0u8; 32];
        kdf.derive(b"pw", b"salt", 7, &mut trait_out).unwrap();
        let mut free_out = [0u8; 32];
        pbkdf2_hmac_sha256(b"pw", b"salt", 7, &mut free_out).unwrap();
        assert_eq!(trait_out, free_out);
        assert_eq!(trait_out, derive(b"pw", b"salt", 7));
    }
}
