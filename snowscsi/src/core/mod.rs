//! Core contract layer: errors, device lifecycle, permits and values.
//!
//! This is the `no_std`, allocation-free, `unsafe`-free vocabulary layer of the
//! P1 API (`__ARCH__/design/02-api.md` §4 and
//! `__ARCH__/design/02-api-core.md` §4.7–§4.18). It contains only pure values
//! and seams:
//!
//! - [`errors`] — [`Sense`]/[`Completion`]/[`Fault`], the `storage_fault_sense`
//!   table and `commit_fault` (§4.17);
//! - [`device`] — the [`Device`] lifecycle trait, [`NoMedium`]/[`Pair`] and the
//!   static [`InquiryData`]/[`RemovalEncoding`] descriptors (§4.1/§4.2);
//! - [`profile`] — the defaulted [`SpcProfile`] capability seam for the public
//!   query commands (§4.19 extension clause);
//! - [`permit`] — privately minted permits and [`ExecutionGuard`] (§4.8/§4.11);
//! - [`long`], [`management`], [`ua`], [`eject`] — long-operation, management,
//!   unit-attention and eject values (§4.7/§4.12–§4.14);
//! - [`storage`] — [`Storage`](storage::Storage)/[`HostTransport`](storage::HostTransport)
//!   and their synchronous adapters (§4.5/§4.6);
//! - [`collections`], [`lu`], [`runner`], [`target`] — slot sets, the `Lu`
//!   seam, the runner state machine and the `Target`/`StaticTarget` entries
//!   (§4.3/§4.9/§4.11/§4.20);
//! - [`spc`] — the six-command public `Spc` wrapper (§4.19).
//!
//! The core layer holds no executor task, no buffer ownership and no profile
//! behaviour; buffers are re-borrowed by the caller on every poll.
//!
//! # Path ambiguity with the `core` crate
//!
//! This module is named `core`, so inside it always spell the language crate as
//! `::core::…`; a bare `core::…` in this tree risks resolving ambiguously.

pub mod collections;
pub mod device;
pub mod eject;
pub mod errors;
pub mod long;
pub mod lu;
pub mod management;
pub mod permit;
pub mod profile;
pub mod runner;
pub mod spc;
pub mod storage;
pub mod target;
pub mod ua;

pub use self::collections::{cons, At, Cons, Here, Index, Nil, RuntimeSet, SlotSet, There};
pub use self::device::{
    Admission, CommandContext, Control, DataPlan, Device, Direction, Feedback, FeedbackKind,
    InquiryData, InterruptReason, NoMedium, Pair, PollStep, RemovalEncoding, TargetId, Writability,
};
pub use self::eject::{decide_eject, EjectDecision, EjectOrigin, RemovalLocks};
pub use self::errors::{
    commit_fault, storage_fault_sense, Completion, Delivery, Effect, Fault, IoContext,
    KnownEffects, Sense, ABORTED_COMMAND, COMMAND_ABORTED, FORMAT_IN_PROGRESS, ILLEGAL_REQUEST,
    INTERNAL_FAILURE, INVALID_FIELD, LBA_OUT_OF_RANGE, LUN_NOT_SUPPORTED, MEDIUM_ERROR,
    MEDIUM_NOT_PRESENT, MEDIUM_REMOVAL_PREVENTED, NEEDS_RECOVERY, WRITE_ERROR, WRITE_PROTECTED,
};
pub use self::long::{LongInfo, LongPhase};
pub use self::lu::{Lu, LuImpl};
pub use self::management::{BoundaryReject, Change, ChangeResult, LuInfo};
pub use self::permit::{BoundaryPermit, CommandPermit, ExecutionGuard, OwnerBindPermit};
pub use self::profile::{Capacity, SpcProfile};
pub use self::runner::{DriveStep, RunEnd, RunOutcome, Runner};
pub use self::spc::Spc;
pub use self::target::{StaticTarget, Target};
pub use self::ua::{ClearReason, ClearRule, Ua, UaClass, UaSet};
