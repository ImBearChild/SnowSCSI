//! Hardware AES-256 for the SD plane: a [`CtrAccel`] over the P4 AES-DMA.
//!
//! The ESP32-P4 has an AES accelerator with a DMA path
//! (`esp_hal::aes::dma::AesDma`). This module wraps it in the two hooks
//! `snowscsi`'s offset-addressed cipher layer needs:
//!
//! * [`BlockCipher16::encrypt_block`] — one block, hardware **ECB**. Used for
//!   the unaligned head/tail of a CTR range.
//! * [`CtrAccel::ctr_xor_aligned`] — whole blocks, hardware **CTR**. Used for
//!   the aligned middle.
//!
//! The offset → counter-block mapping (`nonce || BE64(off / 16)`) and the
//! head/tail handling stay in [`snowscsi::common::cipher::AesCtr`]; this type
//! only ever sees a prepared counter block.
//!
//! # Busy-wait with a deadline
//!
//! `AesTransfer::wait()` is a **poll loop** on the peripheral's status
//! register: it spins on the calling task and does not yield to the executor.
//! The firmware is single-threaded (one `join4` future), so a short wait is
//! simply CPU time in the storage worker's read/write call, not a lost
//! wakeup. It is nevertheless **bounded**: [`P4Aes`] polls
//! [`AesTransfer::is_done`] against a 100 ms deadline *before* calling
//! `wait()`. A transfer that misses the deadline is dropped (a dropped
//! transfer cannot return the driver or the DMA buffers), the primitive is
//! **poisoned**, and the call returns [`CipherError::Backend`]. Every later
//! call returns the same error, so a stuck engine becomes storage I/O errors
//! instead of a hung executor.
//!
//! `AesDma::process` also **resets the AES peripheral on every call** (esp-hal
//! does this internally, once per `process`), so an *aligned* 16 KiB
//! operation split into 2 KiB chunks pays eight resets. An unaligned range
//! adds one ECB transfer for the head and one for the partial tail, and a run
//! that would cross the hardware's 32-bit counter wrap is split again (see
//! [`P4Aes::ctr_xor_aligned`]), so the transfer count is not exactly
//! `len / AES_BUF` in general. Larger chunks amortise the resets at the cost
//! of static DMA RAM and (for writes) caller stack; see
//! [`crate::store::CIPHER_SCRATCH`].
//!
//! # Buffers
//!
//! The TX and RX DMA buffers are **static** (`dma_tx_buffer!` /
//! `dma_rx_buffer!`, hence `AES_BUF` bytes each in `.bss`), not stack locals:
//! they must live in DMA-capable internal RAM (the P4's DMA bounces PSRAM
//! access through extra descriptors), and the main task's stack is small.
//! They are moved in and out of the driver on every transfer (`Option` +
//! `take`), because `AesDma::process` consumes the driver and its buffers and
//! hands them back through `AesTransfer::wait()`.
//!
//! The two statics are linked unconditionally — even when `CIPHER_KEY` is
//! `None` in `src/main.rs` and the plane is served plaintext — because the
//! macros expand inside this module and do not depend on runtime use. Turning
//! encryption off therefore saves the AES work, not the 4 KiB of `.bss`.

use core::hint::spin_loop;

use defmt::{error, info};
use embassy_time::{Duration, Instant};

use esp_hal::aes::cipher_modes::{Ctr, Ecb};
use esp_hal::aes::dma::{AesDma, AesDmaChannel, DmaCipherState};
use esp_hal::aes::Aes;
use esp_hal::aes::Operation;
use esp_hal::dma::{DmaRxBuf, DmaTxBuf};

use snowscsi::common::cipher::{AesCtr, BlockCipher16, CipherError, CtrAccel, StreamCipher};

/// Size of each of the two DMA buffers (TX and RX), in bytes.
///
/// A multiple of the AES block size, so a transfer never ends mid-block, and
/// large enough that the per-transfer peripheral reset is amortised over more
/// than one or two blocks. Both buffers live in `.bss` (statically allocated
/// by `dma_tx_buffer!` / `dma_rx_buffer!`); raise this only together with
/// [`crate::store::CIPHER_SCRATCH`] if throughput measurements ask for it.
pub const AES_BUF: usize = 2048;

// The chunking below assumes the DMA buffer holds whole blocks and is big
// enough to be worth a transfer.
const _: () = assert!(AES_BUF >= 2048 && AES_BUF % 16 == 0);

/// How long a hardware transfer may take before it is declared stuck.
///
/// A 2 KiB AES-DMA pass takes tens of microseconds on the P4; 100 ms is far
/// above any legitimate transfer, so hitting it means the peripheral or its
/// DMA channel is not completing. The transfer is then dropped and the
/// primitive poisoned (see the module docs).
const TRANSFER_TIMEOUT: Duration = Duration::from_millis(100);

/// Hardware AES-CTR/ECB primitive for the encrypted SD plane.
///
/// Construct once (during bring-up), run [`Self::self_test`], then move it
/// into the cipher plane. [`Self::new`] must be called **once per boot**: the
/// `dma_tx_buffer!` / `dma_rx_buffer!` macros hand out one static DMA buffer
/// each, so a second call would alias the first instance's DMA memory.
///
/// All key material stays in ordinary RAM — the module docs of
/// `snowscsi::common::cipher` explain that this is best-effort, not zeroize.
/// Every fallible path returns [`Error`] or [`CipherError`]; there is **no
/// panic path for valid parameters**.
pub struct P4Aes {
    /// The DMA-enabled driver, parked while a transfer owns it.
    aes: Option<AesDma<'static>>,
    /// Plaintext → peripheral buffer.
    tx: Option<DmaTxBuf>,
    /// Peripheral → ciphertext buffer.
    rx: Option<DmaRxBuf>,
    /// AES-256 key (32 bytes). Not scrubbed on drop; see the module docs.
    key: [u8; 32],
    /// A transfer timed out; the driver and both buffers are gone.
    poisoned: bool,
}

/// [`P4Aes`] construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Error {
    /// A statically allocated DMA buffer was rejected by the DMA driver
    /// (wrong memory region or alignment).
    DmaBuffer,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DmaBuffer => write!(f, "AES DMA buffer allocation failed"),
        }
    }
}

impl P4Aes {
    /// Build the hardware AES-256 engine with two static DMA buffers.
    ///
    /// `aes` is the AES peripheral singleton and `dma` a channel the AES
    /// peripheral can drive. On the ESP32-P4 that is the AXI GDMA engine, so
    /// the caller passes `peripherals.DMA_AXI_CH0` (not the AHB `DMA_CH0`).
    ///
    /// Call this **once per boot**. The DMA buffer macros allocate one static
    /// buffer (and descriptor set) each; a second call would hand out the same
    /// memory while the first [`P4Aes`] still owns it. Setup errors (the DMA
    /// driver rejecting a buffer) are returned, not panicked on.
    pub fn new(
        aes: esp_hal::peripherals::AES<'static>,
        dma: impl AesDmaChannel<'static>,
        key: [u8; 32],
    ) -> Result<Self, Error> {
        let tx = esp_hal::dma_tx_buffer!(AES_BUF).map_err(|_| Error::DmaBuffer)?;
        let rx = esp_hal::dma_rx_buffer!(AES_BUF).map_err(|_| Error::DmaBuffer)?;
        Ok(Self {
            aes: Some(Aes::new(aes).with_dma(dma)),
            tx: Some(tx),
            rx: Some(rx),
            key,
            poisoned: false,
        })
    }

    /// Hardware AES-256 self-test (known-answer tests).
    ///
    /// Temporarily installs a fixed KAT key (not the production key), then:
    ///
    /// 1. runs the hardware CTR path against the NIST SP 800-38A F.5.5
    ///    AES-256-CTR keystream (`f0f1…feff` counter),
    /// 2. runs it again with the counter block `nonce||BE64(1)`, i.e. block 1
    ///    of the layout [`AesCtr`] produces,
    /// 3. drives the same neighbouring counter blocks through
    ///    `AesCtr::xor` at **byte offset 17** (a length of 33 bytes), so the
    ///    unaligned head, the aligned DMA middle and the partial tail are all
    ///    compared against the precomputed keystream,
    /// 4. runs a four-block vector whose counter starts at
    ///    `nonce||BE64(0xFFFF_FFFE)`. The hardware only carries the low 32
    ///    counter bits (INC_32), so this crosses the wrap that the old
    ///    "trust the peripheral to increment 128 bits" assumption got wrong.
    /// 5. runs `AES_BUF + 16` zero bytes from `nonce||BE64(0xFFFF_FFFF)`,
    ///    i.e. 129 blocks with one 32-bit wrap, and checks the blocks around
    ///    the wrap plus the last block against the precomputed keystream. This
    ///    exercises the full-buffer chunking *and* the manual 128-bit counter
    ///    advance.
    ///
    /// Returns `false` on any mismatch or backend error; the caller must not
    /// serve encrypted media in that case. The production key is restored
    /// before returning, even on failure.
    pub fn self_test(&mut self) -> bool {
        let saved = self.key;
        self.key = KAT_KEY;
        let ok = self.self_test_inner();
        self.key = saved;
        if ok {
            info!("AES hardware KAT: PASS");
        } else {
            error!("AES hardware KAT: FAIL");
        }
        ok
    }

    /// KAT body; `self.key` is already the fixed test key.
    fn self_test_inner(&mut self) -> bool {
        // 1. Hardware CTR, the NIST F.5.5 counter block.
        let mut buf = [0u8; 64];
        if self.ctr_xor_aligned(KAT_CTR0, &mut buf).is_err() || buf != KAT_KS0 {
            return false;
        }

        // 2. Hardware CTR, `nonce || BE64(1)` — the block `AesCtr` feeds for
        //    image offset 16.
        let mut buf = [0u8; 64];
        if self.ctr_xor_aligned(KAT_CTR1, &mut buf).is_err() || buf != KAT_KS1 {
            return false;
        }

        // 3. The composed stream cipher at an unaligned offset: 33 bytes from
        //    image offset 17 = KAT_KS1[1..34] (block 1 byte 1 onwards).
        {
            let mut buf = [0u8; 33];
            let mut ctr = AesCtr::new(Borrowed(self), KAT_NONCE);
            if ctr.xor(17, &mut buf).is_err() {
                return false;
            }
            if buf[..] != KAT_KS1[1..34] {
                return false;
            }
        }

        // 4. Low-32-bit counter wrap: four blocks from 0xFFFF_FFFE. A hardware
        //    INC_128 assumption makes blocks 3 and 4 wrong (they would repeat
        //    the 0x...0000/0x...0001 counters instead of carrying to
        //    0x1_0000_0000/0x1_0000_0001).
        let mut buf = [0u8; 64];
        if self.ctr_xor_aligned(KAT_CTR_WRAP, &mut buf).is_err() || buf != KAT_KS_WRAP {
            return false;
        }

        // 5. More than one DMA buffer with a wrap inside it: 129 blocks from
        //    0xFFFF_FFFF. The first run is capped at one block, then the
        //    manual 128-bit advance resumes at 0x1_0000_0000 for the remaining
        //    128 blocks. The first 48 bytes must therefore repeat the last
        //    three blocks of KAT_KS_WRAP (this is where an INC_32 hardware run
        //    would wrap instead of carry), and the last block proves the whole
        //    `AES_BUF` chunk moved the counter correctly.
        let mut buf = [0u8; AES_BUF + 16];
        if self.ctr_xor_aligned(KAT_CTR_WRAP1, &mut buf).is_err() {
            return false;
        }
        if buf[..48] != KAT_KS_WRAP[16..64] {
            return false;
        }
        if buf[AES_BUF..] != KAT_KS_WRAP_LAST {
            return false;
        }

        true
    }

    /// Reject every call once the primitive is poisoned.
    ///
    /// The driver and both DMA buffers were dropped with the timed-out
    /// transfer, so there is nothing left to run a transfer on.
    fn ensure_ready(&self) -> Result<(), CipherError> {
        if self.poisoned {
            Err(CipherError::Backend)
        } else {
            Ok(())
        }
    }

    /// Take the driver and both buffers, or fail without panicking.
    ///
    /// A poisoned primitive has neither: the timed-out transfer dropped them.
    fn take_parts(&mut self) -> Result<(AesDma<'static>, DmaTxBuf, DmaRxBuf), CipherError> {
        if self.poisoned {
            return Err(CipherError::Backend);
        }
        match (self.aes.take(), self.tx.take(), self.rx.take()) {
            (Some(aes), Some(tx), Some(rx)) => Ok((aes, tx, rx)),
            // Put back whatever was still present; a `None` here only happens
            // if a previous error path failed to restore the parts.
            (aes, tx, rx) => {
                self.aes = aes;
                self.tx = tx;
                self.rx = rx;
                Err(CipherError::Backend)
            }
        }
    }

    /// Run one hardware pass over `blocks` blocks already staged in `tx`.
    ///
    /// On success the output is in `rx`; on any DMA error the driver and both
    /// buffers are put back and [`CipherError::Backend`] is returned. The
    /// peripheral is reset by `AesDma::process` at the start of every call.
    ///
    /// The transfer is polled against [`TRANSFER_TIMEOUT`]. If it misses the
    /// deadline, the transfer is dropped (taking the driver and both buffers
    /// with it), the primitive is poisoned, and every later call returns
    /// [`CipherError::Backend`] rather than hanging the executor.
    fn process(&mut self, blocks: usize, state: &DmaCipherState) -> Result<(), CipherError> {
        let len = blocks * 16;
        let (aes, mut tx, mut rx) = self.take_parts()?;
        tx.set_length(len);
        rx.set_length(len);
        match aes.process(blocks, rx, tx, Operation::Encrypt, state, self.key) {
            Ok(transfer) => {
                // Bounded poll loop (see the module docs): never call the
                // unbounded `wait()` probe on a peripheral that may be stuck.
                let deadline = Instant::now().saturating_add(TRANSFER_TIMEOUT);
                while !transfer.is_done() {
                    if Instant::now() >= deadline {
                        // Dropping stops both DMA channels and drops the
                        // driver; the buffers are gone with it.
                        drop(transfer);
                        self.poisoned = true;
                        return Err(CipherError::Backend);
                    }
                    spin_loop();
                }
                let (aes, rx, tx) = transfer.wait();
                // A short RX count means the DMA did not deliver the whole
                // block run; the subset of RX bytes that did arrive is not
                // usable as a keystream.
                if rx.number_of_received_bytes() != len {
                    self.aes = Some(aes);
                    self.rx = Some(rx);
                    self.tx = Some(tx);
                    return Err(CipherError::Backend);
                }
                self.aes = Some(aes);
                self.rx = Some(rx);
                self.tx = Some(tx);
                Ok(())
            }
            Err((_dma, aes, rx, tx)) => {
                self.aes = Some(aes);
                self.rx = Some(rx);
                self.tx = Some(tx);
                Err(CipherError::Backend)
            }
        }
    }

    /// Copy `n` (≤ `AES_BUF`) output bytes out of the RX buffer.
    fn take_rx(&self, dst: &mut [u8]) -> Result<(), CipherError> {
        let rx = self.rx.as_ref().ok_or(CipherError::Backend)?;
        let src = rx.as_slice();
        let n = dst.len();
        if src.len() < n {
            return Err(CipherError::Backend);
        }
        dst.copy_from_slice(&src[..n]);
        Ok(())
    }
}

impl BlockCipher16 for P4Aes {
    /// Encrypt one 16-byte block with hardware AES-ECB.
    ///
    /// The block is copied into the static TX buffer, one block is DMA'd
    /// through the peripheral, and the RX block is copied back into `block`.
    /// A DMA error maps to [`CipherError::Backend`]; no panic path exists for
    /// valid parameters. A poisoned primitive returns `Backend` without
    /// touching `block`.
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
        self.ensure_ready()?;
        {
            let tx = self.tx.as_mut().ok_or(CipherError::Backend)?;
            tx.fill(block);
        }
        self.process(1, &DmaCipherState::from(Ecb))?;
        self.take_rx(block)
    }
}

impl CtrAccel for P4Aes {
    /// XOR the hardware CTR keystream into a whole number of blocks.
    ///
    /// `buf` is split into runs of at most [`AES_BUF`] **and** at most the
    /// distance to the next wrap of the counter's low 32 bits. The vendored
    /// esp-hal clears `inc_sel` for CTR (`set_cipher_mode`), which selects
    /// **INC_32**: the peripheral carries only `counter[12..16]`, so a run
    /// that crossed a 32-bit low-word boundary would repeat counters instead
    /// of advancing the 128-bit word. After every hardware run the full
    /// 128-bit counter is advanced here with [`advance_be`], which is what
    /// makes the stream match [`AesCtr`]'s documented `nonce || BE64(block)`
    /// layout. Each run is copied into TX, encrypted by the peripheral, and
    /// copied back out of RX.
    ///
    /// An empty buffer is a no-op; a non-multiple of 16 is
    /// [`CipherError::BadParameters`]. A poisoned primitive (a previous
    /// transfer timed out) returns [`CipherError::Backend`].
    fn ctr_xor_aligned(&mut self, counter: [u8; 16], buf: &mut [u8]) -> Result<(), CipherError> {
        self.ensure_ready()?;
        if !buf.len().is_multiple_of(16) {
            return Err(CipherError::BadParameters);
        }
        if buf.is_empty() {
            return Ok(());
        }

        let mut counter = counter;
        let mut done = 0usize;
        while done < buf.len() {
            // INC_32: the low 32 bits wrap at 2^32. A run may contain at most
            // that many blocks before the peripheral would restart them.
            let low = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
            let max_blocks = if low == 0 {
                1u64 << 32
            } else {
                (1u64 << 32) - u64::from(low)
            };
            let remaining_blocks = ((buf.len() - done) / 16) as u64;
            let room_blocks = (AES_BUF / 16) as u64;
            let blocks =
                core::cmp::min(core::cmp::min(room_blocks, max_blocks), remaining_blocks) as usize;
            let n = blocks * 16;
            let chunk = &mut buf[done..done + n];
            {
                let tx = self.tx.as_mut().ok_or(CipherError::Backend)?;
                tx.fill(chunk);
            }
            // A fresh `Ctr` per run: the counter we hand over is the exact
            // first block of this run, and the peripheral increments only
            // within it.
            self.process(blocks, &DmaCipherState::from(Ctr::new(counter)))?;
            self.take_rx(chunk)?;
            advance_be(&mut counter, blocks as u64);
            done += n;
        }
        Ok(())
    }
}

/// Add `blocks` to a 128-bit big-endian counter.
///
/// The low 64 bits carry into the high 64 bits. In practice an image would
/// need 2⁶⁴ blocks before the carry reaches the nonce, but carrying is cheaper
/// than documenting a lie.
fn advance_be(counter: &mut [u8; 16], blocks: u64) {
    let mut low = [0u8; 8];
    low.copy_from_slice(&counter[8..]);
    let (sum, carry) = u64::from_be_bytes(low).overflowing_add(blocks);
    counter[8..].copy_from_slice(&sum.to_be_bytes());
    if carry {
        let mut high = [0u8; 8];
        high.copy_from_slice(&counter[..8]);
        let (sum, _) = u64::from_be_bytes(high).overflowing_add(1);
        counter[..8].copy_from_slice(&sum.to_be_bytes());
    }
}

/// Adapter that borrows the live primitive so [`AesCtr`] can be exercised
/// during the self-test without moving `P4Aes` out of its owner.
struct Borrowed<'a>(&'a mut P4Aes);

impl BlockCipher16 for Borrowed<'_> {
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CipherError> {
        self.0.encrypt_block(block)
    }
}

impl CtrAccel for Borrowed<'_> {
    fn ctr_xor_aligned(&mut self, counter: [u8; 16], buf: &mut [u8]) -> Result<(), CipherError> {
        self.0.ctr_xor_aligned(counter, buf)
    }
}

/// NIST SP 800-38A F.5.5 AES-256 key (test vector, not a secret).
const KAT_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];

/// `f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`.
const KAT_CTR0: [u8; 16] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

/// AES-256 keystream for the four blocks starting at [`KAT_CTR0`].
const KAT_KS0: [u8; 64] = [
    0x0b, 0xdf, 0x7d, 0xf1, 0x59, 0x17, 0x16, 0x33, 0x5e, 0x9a, 0x8b, 0x15, 0xc8, 0x60, 0xc5, 0x02,
    0x5a, 0x6e, 0x69, 0x9d, 0x53, 0x61, 0x19, 0x06, 0x54, 0x33, 0x86, 0x3c, 0x8f, 0x65, 0x7b, 0x94,
    0x1b, 0xc1, 0x2c, 0x9c, 0x01, 0x61, 0x0d, 0x5d, 0x0d, 0x8b, 0xd6, 0xa3, 0x37, 0x8e, 0xca, 0x62,
    0x29, 0x56, 0xe1, 0xc8, 0x69, 0x35, 0x36, 0xb1, 0xbe, 0xe9, 0x9c, 0x73, 0xa3, 0x15, 0x76, 0xb6,
];

/// `nonce = 00000000000000ff`, block index 1: the counter `AesCtr` uses for
/// image offset 16 with that nonce.
const KAT_CTR1: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Keystream for blocks 1..=4 of the `KAT_NONCE` layout (64 bytes).
const KAT_KS1: [u8; 64] = [
    0x01, 0xd2, 0x8a, 0xc3, 0xa9, 0x45, 0xe3, 0x6e, 0xc1, 0xe5, 0xdf, 0xc3, 0xb1, 0xc2, 0x0c, 0x3f,
    0xf8, 0xad, 0x0f, 0xae, 0x6c, 0xf9, 0x1b, 0xab, 0x22, 0x09, 0x2c, 0xdb, 0xb0, 0x5e, 0x8f, 0x64,
    0x19, 0x63, 0x25, 0x6d, 0x33, 0x6e, 0x06, 0x6f, 0x20, 0x87, 0x5e, 0xbe, 0x4a, 0x1e, 0x52, 0x17,
    0x95, 0x1b, 0x6a, 0xc0, 0x45, 0xe3, 0x25, 0x7d, 0x9f, 0x2f, 0x36, 0x78, 0xc2, 0xf9, 0x9e, 0x86,
];

/// The nonce half of [`KAT_CTR1`].
const KAT_NONCE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

/// `nonce || BE64(0xFFFF_FFFE)`: four blocks ending at the 32-bit wrap boundary.
const KAT_CTR_WRAP: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
];

/// AES-256 keystream for counters `0xFFFF_FFFE..=0x1_0000_0001`.
///
/// Blocks 3 and 4 prove the 128-bit carry: a peripheral left on INC_32 would
/// have wrapped the low word back to 0 instead of carrying into
/// `counter[8..12]`.
const KAT_KS_WRAP: [u8; 64] = [
    0x4b, 0x56, 0xcd, 0xb2, 0x57, 0xd2, 0xbf, 0x6a, 0xd7, 0xb3, 0x3a, 0x15, 0xdc, 0x64, 0xa4, 0xea,
    0x50, 0x82, 0x5e, 0xbb, 0x4a, 0x26, 0x11, 0x8a, 0xbd, 0xcd, 0xb2, 0x95, 0xcd, 0x7e, 0xca, 0x36,
    0x28, 0x39, 0x57, 0x74, 0x8a, 0xbd, 0xa7, 0x54, 0x0f, 0x0d, 0xde, 0xd5, 0x79, 0x02, 0xa7, 0xa9,
    0xe8, 0xae, 0xe0, 0x95, 0xcc, 0x5d, 0x0b, 0x3a, 0x96, 0xa6, 0x5d, 0x37, 0x92, 0x91, 0x20, 0x99,
];

/// `nonce || BE64(0xFFFF_FFFF)`: the first block of the `AES_BUF + 16` KAT.
const KAT_CTR_WRAP1: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// AES-256 keystream for `nonce || BE64(0x1_0000_007F)`, the 129th block of
/// the `AES_BUF + 16` run from [`KAT_CTR_WRAP1`].
const KAT_KS_WRAP_LAST: [u8; 16] = [
    0x92, 0x3e, 0x8f, 0xc8, 0x25, 0x10, 0x33, 0x6c, 0x24, 0x6b, 0x5d, 0x7a, 0xcb, 0x2d, 0x18, 0xd4,
];
