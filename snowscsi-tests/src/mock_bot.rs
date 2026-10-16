//! Mock bulk driver + control gadget for deterministic, poll-driven BOT
//! integration tests (mirrors `MockConn`'s scripted-byte-stream approach).
//!
//! The host side of each test feeds bytes into `MockBotIo` and inspects the
//! accumulated `in_` bytes; control requests are injected into `MockGadget`
//! with recording ack/reply handles.

use core::time::Duration;

use snowscsi::usb::{BotIo, BotIoErr, CtrlAck, CtrlReply, CtrlReq, Gadget};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Scripted bulk-OUT / bulk-IN driver.
#[derive(Default)]
pub struct MockBotIo {
    /// host → device bytes queued for the OUT endpoint.
    out: VecDeque<u8>,
    /// device → host bytes accumulated on the IN endpoint (data + CSWs).
    pub in_: Vec<u8>,
    /// Number of times `stall_both` succeeded.
    pub stall_count: u32,
    /// Whether `stall_both` reports success (default: yes).
    pub stall_available: bool,
    /// Number of times `stall_in` succeeded.
    pub stall_in_count: u32,
    /// Whether `stall_in` reports success (default: yes).
    pub stall_in_available: bool,
}

impl MockBotIo {
    pub fn new() -> Self {
        Self {
            stall_available: true,
            stall_in_available: true,
            ..Default::default()
        }
    }

    /// Queue host → device bytes (a CBW or a Data-Out chunk).
    pub fn feed_out(&mut self, bytes: &[u8]) {
        self.out.extend(bytes);
    }

    /// Whether `stall_in` reports success (default: yes).
    pub fn set_stall_in(mut self, available: bool) -> Self {
        self.stall_in_available = available;
        self
    }

    /// Drain and return everything the device has sent so far.
    pub fn take_sent(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.in_)
    }

    fn serve(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        if self.out.is_empty() {
            return Err(BotIoErr::WouldBlock);
        }
        let n = self.out.len().min(buf.len());
        for (i, b) in self.out.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }
}

impl BotIo for MockBotIo {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        self.serve(buf)
    }

    fn recv_out(&mut self, buf: &mut [u8], _timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        self.serve(buf)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.in_.extend_from_slice(buf);
        Ok(())
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        if self.stall_available {
            self.stall_count += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn stall_in(&mut self) -> Result<(), ()> {
        if self.stall_in_available {
            self.stall_in_count += 1;
            Ok(())
        } else {
            Err(())
        }
    }

    fn can_stall_in(&self) -> bool {
        self.stall_in_available
    }
}

/// Recording ack handle (records through `Arc`, since `ack` consumes self).
#[derive(Clone, Default)]
pub struct MockAck {
    pub acked: Arc<AtomicBool>,
}

impl MockAck {
    pub fn new() -> Self {
        Self {
            acked: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl CtrlAck for MockAck {
    fn ack(self) {
        self.acked.store(true, Ordering::SeqCst);
    }
}

/// Recording reply handle.
#[derive(Clone, Default)]
pub struct MockReply {
    pub sent: Arc<Mutex<Vec<u8>>>,
}

impl MockReply {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl CtrlReply for MockReply {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        self.sent.lock().unwrap().extend_from_slice(data);
        Ok(())
    }
}

/// Scripted control gadget: pops pre-injected requests.
#[derive(Default)]
pub struct MockGadget {
    pub ctrl_queue: VecDeque<CtrlReq<MockAck, MockReply>>,
}

impl MockGadget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject(&mut self, req: CtrlReq<MockAck, MockReply>) {
        self.ctrl_queue.push_back(req);
    }
}

impl<'a> Gadget<'a> for MockGadget {
    type Ack = MockAck;
    type Reply = MockReply;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<MockAck, MockReply>> {
        self.ctrl_queue.pop_front()
    }
}
