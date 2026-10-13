//! Control-plane (ep0) driver seam for the BOT class requests.
//!
//! [`Gadget`] hands the driver loop the next setup event as a [`CtrlReq`];
//! each request carries a response handle **by value** because the platform
//! control channel borrows the endpoint object and cannot be stored away
//! (PC: FunctionFS `CtrlSender` / `CtrlReceiver`; embedded: MCU control
//! endpoint). The driver must therefore handle a request immediately.
//!
//! Reset / Get Max LUN arrive out-of-band at any time (even mid data
//! phase); the driver loop drains this seam between bulk operations and
//! reacts synchronously — [`crate::usb::target::BotSession::reset`] for a
//! reset, [`crate::usb::target::BotSession::max_lun`] for Get Max LUN.

/// Response handle for Get Max LUN: send the 1-byte answer.
#[allow(clippy::result_unit_err)]
pub trait CtrlReply {
    /// Send `data` and complete the control transfer. `Err(())` on a
    /// transport failure (e.g. short write beyond `wLength`).
    fn send(&mut self, data: &[u8]) -> Result<(), ()>;
}

/// Acknowledgment handle for Bulk-Only Reset. Call after
/// [`BotSession::reset`](crate::usb::target::BotSession::reset) — the
/// control status stage must not complete until the reset is done
/// (BOT §6.4).
pub trait CtrlAck {
    /// Consume the handle and complete the control status stage.
    fn ack(self);
}

/// A control request lifted from the platform's setup events.
///
/// `A` / `R` are the platform's ack / reply handles; the borrow of the
/// platform control channel lives inside them (see [`Gadget`]).
pub enum CtrlReq<A: CtrlAck, R: CtrlReply> {
    /// Bulk-Only Mass Storage Reset (bRequest 0xFF). The driver must call
    /// `BotSession::reset()` before `ack.ack()` (BOT §3.1).
    BotReset { ack: A },
    /// Get Max LUN (bRequest 0xFE). Reply immediately with
    /// `[session.max_lun()]`; never STALL this request (§4.3).
    GetMaxLun { reply: R },
    /// Link-level event (bind / enable / disable) — equivalent to a reset.
    LinkReset,
}

/// The control-plane driver seam.
///
/// `'a` ties the returned handles to the `&mut self` borrow: on FunctionFS
/// the `CtrlSender`/`CtrlReceiver` borrow the `Custom` endpoint object, so
/// a request cannot outlive the borrow and must be handled immediately.
pub trait Gadget<'a> {
    type Ack: CtrlAck;
    type Reply: CtrlReply;

    /// Non-blocking: the next control request, if any.
    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<Self::Ack, Self::Reply>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// Recording ack handle (records via `Rc`, since `ack` consumes self).
    struct MockAck {
        acked: Rc<Cell<bool>>,
    }

    impl CtrlAck for MockAck {
        fn ack(self) {
            self.acked.set(true);
        }
    }

    /// Recording reply handle.
    struct MockReply {
        sent: Rc<RefCell<Vec<u8>>>,
    }

    impl CtrlReply for MockReply {
        fn send(&mut self, data: &[u8]) -> Result<(), ()> {
            self.sent.borrow_mut().extend_from_slice(data);
            Ok(())
        }
    }

    /// Scripted gadget: pops pre-injected requests.
    struct MockGadget {
        queue: VecDeque<CtrlReq<MockAck, MockReply>>,
    }

    impl<'a> Gadget<'a> for MockGadget {
        type Ack = MockAck;
        type Reply = MockReply;

        fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<MockAck, MockReply>> {
            self.queue.pop_front()
        }
    }

    #[test]
    fn bot_reset_ack_consumes_handle() {
        let acked = Rc::new(Cell::new(false));
        let req: CtrlReq<MockAck, MockReply> = CtrlReq::BotReset {
            ack: MockAck {
                acked: acked.clone(),
            },
        };
        match req {
            CtrlReq::BotReset { ack } => ack.ack(),
            _ => unreachable!(),
        }
        assert!(acked.get(), "ack must be recorded once consumed");
    }

    #[test]
    fn get_max_lun_reply_sends_bytes() {
        let sent = Rc::new(RefCell::new(Vec::new()));
        let req: CtrlReq<MockAck, MockReply> = CtrlReq::GetMaxLun {
            reply: MockReply { sent: sent.clone() },
        };
        match req {
            CtrlReq::GetMaxLun { mut reply } => {
                assert!(reply.send(&[0u8]).is_ok());
            }
            _ => unreachable!(),
        }
        assert_eq!(sent.borrow().as_slice(), &[0u8]);
    }

    #[test]
    fn try_next_ctrl_pops_in_order() {
        let mut g = MockGadget {
            queue: VecDeque::from([
                CtrlReq::LinkReset,
                CtrlReq::BotReset {
                    ack: MockAck {
                        acked: Rc::new(Cell::new(false)),
                    },
                },
            ]),
        };
        assert!(matches!(g.try_next_ctrl(), Some(CtrlReq::LinkReset)));
        assert!(matches!(g.try_next_ctrl(), Some(CtrlReq::BotReset { .. })));
        assert!(g.try_next_ctrl().is_none());
    }
}
