//! Bulk-I/O driver seam and byte-exact receive helper (BOT data phase).
//!
//! [`BotIo`] is the transport-facing half of the BOT abstraction: bulk OUT
//! receive (non-blocking + timeout variants) and bulk IN send, plus the
//! optional STALL capability used *only* for invalid CBWs (BOT §6.6.1).
//! The protocol core (`crate::usb::target::BotSession`) never touches this
//! trait directly — it is driven by
//! [`SessionEvent`](crate::usb::target::SessionEvent)s. Drivers (PC FunctionFS
//! endpoints, embedded MCU USB peripherals) and the blocking `step` wrapper
//! consume it.
//!
//! Like [`crate::iscsi::conn::Conn`], error kinds are deliberately coarse:
//! any real I/O failure means the link is dead and the driver should stop.
//! The one exception is [`BotIoErr::Disconnected`]: a USB gadget is a
//! persistent physical port, so a host unplug (VM migration / device detach)
//! is expected and recoverable — the driver resets the BOT session and re-arms.

use core::time::Duration;

/// Coarse bulk-I/O error (mirrors the byte-stream `Conn` philosophy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotIoErr {
    /// Non-blocking receive found no data — try again later.
    WouldBlock,
    /// Transport failure (details logged by the transport).
    Io,
    /// The USB link went down (host disconnect / unplug / VM migration).
    /// Unlike [`Self::Io`] this is expected and recoverable: the driver
    /// should reset the BOT session and re-arm the endpoints; I/O resumes
    /// when the host re-attaches (FunctionFS `Bind`/`Enable` events).
    Disconnected,
}

impl core::fmt::Display for BotIoErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WouldBlock => write!(f, "bulk receive would block"),
            Self::Io => write!(f, "bulk I/O failure"),
            Self::Disconnected => write!(f, "USB link disconnected"),
        }
    }
}

impl core::error::Error for BotIoErr {}

/// Bulk-OUT / bulk-IN driver seam.
///
/// No fine-grained `stall_in` / `stall_out` / `clear_stall` methods and no
/// capability probing: STALL is a single optional capability used only for
/// invalid CBWs (the "capability vs policy" split, §4.7). Data-phase errors
/// are never expressed through STALL — they use short packets + CSW
/// status/residue instead (see the [`target`](crate::usb::target) module's
/// "Data-In shortfall policy" for the rationale and the BOT §6.7.2 deviation).
#[allow(clippy::result_unit_err)]
pub trait BotIo {
    /// Non-blocking attempt to receive bulk OUT into `buf`. Returns the
    /// bytes received, or `Err(WouldBlock)` when nothing is available yet.
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr>;

    /// Blocking receive of bulk OUT into `buf`. `timeout == None` blocks
    /// indefinitely; a finite timeout returns `Err(WouldBlock)` when it
    /// expires without data. Returns the bytes received.
    fn recv_out(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, BotIoErr>;

    /// Send a bulk IN packet.
    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr>;

    /// Optional capability: STALL both bulk endpoints (BOT §6.6.1, invalid
    /// CBW only). Unavailable by default; a transport without endpoint
    /// STALL falls back to dropping the invalid CBW.
    fn stall_both(&mut self) -> Result<(), ()> {
        Err(())
    }
}

/// Receive exactly `buf.len()` bytes, looping over partial receives.
///
/// Blocking (no timeout); a zero-byte receive or any I/O error ends the
/// loop with `Err(())` — mirroring `iscsi::conn::read_exact`.
#[allow(clippy::result_unit_err)]
pub fn recv_exact<B: BotIo + ?Sized>(io: &mut B, mut buf: &mut [u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        let n = io.recv_out(buf, None).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::collections::VecDeque;

    /// Scripted bulk driver: serves pre-staged host→device bytes and
    /// records device→host bytes.
    struct FakeIo {
        out: RefCell<VecDeque<u8>>,
        sent: RefCell<Vec<u8>>,
        stall: RefCell<u32>,
    }

    impl FakeIo {
        fn new(out: &[u8]) -> Self {
            Self {
                out: RefCell::new(out.iter().copied().collect()),
                sent: RefCell::new(Vec::new()),
                stall: RefCell::new(0),
            }
        }
    }

    impl BotIo for FakeIo {
        fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
            let mut q = self.out.borrow_mut();
            if q.is_empty() {
                return Err(BotIoErr::WouldBlock);
            }
            let n = q.len().min(buf.len());
            for (i, b) in q.drain(..n).enumerate() {
                buf[i] = b;
            }
            Ok(n)
        }

        fn recv_out(
            &mut self,
            buf: &mut [u8],
            _timeout: Option<Duration>,
        ) -> Result<usize, BotIoErr> {
            self.try_recv_out(buf)
        }

        fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
            self.sent.borrow_mut().extend_from_slice(buf);
            Ok(())
        }

        fn stall_both(&mut self) -> Result<(), ()> {
            *self.stall.borrow_mut() += 1;
            Ok(())
        }
    }

    /// Minimal driver without STALL capability.
    struct NoStall;
    impl BotIo for NoStall {
        fn try_recv_out(&mut self, _buf: &mut [u8]) -> Result<usize, BotIoErr> {
            Err(BotIoErr::WouldBlock)
        }
        fn recv_out(
            &mut self,
            _buf: &mut [u8],
            _timeout: Option<Duration>,
        ) -> Result<usize, BotIoErr> {
            Err(BotIoErr::WouldBlock)
        }
        fn send_in(&mut self, _buf: &[u8]) -> Result<(), BotIoErr> {
            Ok(())
        }
    }

    #[test]
    fn recv_exact_collects_partial_chunks() {
        let mut io = FakeIo::new(&[1, 2, 3, 4, 5]);
        let mut buf = [0u8; 5];
        assert!(recv_exact(&mut io, &mut buf).is_ok());
        assert_eq!(buf, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn recv_exact_serves_multiple_calls() {
        let mut io = FakeIo::new(&[1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; 2];
        assert!(recv_exact(&mut io, &mut buf).is_ok());
        assert_eq!(buf, [1, 2]);
        assert!(recv_exact(&mut io, &mut buf).is_ok());
        assert_eq!(buf, [3, 4]);
        assert!(recv_exact(&mut io, &mut buf).is_ok());
        assert_eq!(buf, [5, 6]);
    }

    #[test]
    fn recv_exact_errors_on_empty_source() {
        let mut io = FakeIo::new(&[]);
        let mut buf = [0u8; 3];
        assert!(recv_exact(&mut io, &mut buf).is_err());
    }

    #[test]
    fn try_recv_out_reports_would_block_when_empty() {
        let mut io = FakeIo::new(&[]);
        let mut buf = [0u8; 4];
        assert_eq!(io.try_recv_out(&mut buf), Err(BotIoErr::WouldBlock));
    }

    #[test]
    fn send_in_accumulates() {
        let mut io = FakeIo::new(&[]);
        assert!(io.send_in(&[0x55, 0x53, 0x42, 0x53]).is_ok());
        assert_eq!(io.sent.borrow().as_slice(), &[0x55, 0x53, 0x42, 0x53]);
    }

    #[test]
    fn stall_both_counts_and_defaults_to_unavailable() {
        let mut io = FakeIo::new(&[]);
        assert!(io.stall_both().is_ok());
        assert_eq!(*io.stall.borrow(), 1);

        // A driver that does not override `stall_both` reports it unavailable.
        let mut no_stall = NoStall;
        assert_eq!(no_stall.stall_both(), Err(()));
    }

    #[test]
    fn io_err_display() {
        assert_eq!(BotIoErr::WouldBlock.to_string(), "bulk receive would block");
        assert_eq!(BotIoErr::Io.to_string(), "bulk I/O failure");
        assert_eq!(BotIoErr::Disconnected.to_string(), "USB link disconnected");
    }
}
