//! Core contract layer: errors, device lifecycle, permits and values.
//!
//! This is the `no_std`, allocation-free, `unsafe`-free vocabulary layer of the
//! public API. It contains only pure values and seams:
//!
//! - [`errors`](crate::core::errors) — [`Sense`](crate::core::Sense) /
//!   [`Completion`](crate::core::Completion) / [`Fault`](crate::core::Fault),
//!   the `storage_fault_sense` table and `commit_fault`;
//! - [`device`](crate::core::device) — the [`Device`](crate::core::Device)
//!   lifecycle trait, [`NoMedium`](crate::core::NoMedium) /
//!   [`Pair`](crate::core::Pair) and the static
//!   [`InquiryData`](crate::core::InquiryData) /
//!   [`RemovalEncoding`](crate::core::RemovalEncoding) descriptors;
//! - [`profile`](crate::core::profile) — the defaulted
//!   [`SpcProfile`](crate::core::SpcProfile) capability seam for the public
//!   query commands (extension clause);
//! - [`permit`](crate::core::permit) — privately minted permits and
//!   [`ExecutionGuard`](crate::core::ExecutionGuard);
//! - [`long`](crate::core::long), [`management`](crate::core::management),
//!   [`ua`](crate::core::ua), [`eject`](crate::core::eject) — long-operation,
//!   management, unit-attention and eject values;
//! - [`async_wake`](crate::core::async_wake) — the waker-based completion seam
//!   for asynchronous shells
//!   ([`AsyncWake`](crate::core::async_wake::AsyncWake) /
//!   [`wait`](crate::core::async_wake::wait));
//! - [`storage`](crate::core::storage) —
//!   [`Storage`](crate::core::storage::Storage) /
//!   [`HostTransport`](crate::core::storage::HostTransport) and their
//!   synchronous adapters;
//! - [`slots`](crate::core::slots) — the runtime-free asynchronous slot
//!   adapter ([`SlotPool`](crate::core::slots::SlotPool) →
//!   [`SlotStore`](crate::core::slots::SlotStore) /
//!   [`SlotTask`](crate::core::slots::SlotTask));
//! - [`collections`](crate::core::collections), [`lu`](crate::core::lu),
//!   [`runner`](crate::core::runner), [`target`](crate::core::target) — slot
//!   sets, the `Lu` seam, the runner state machine and the
//!   `Target`/`StaticTarget` entries;
//! - [`spc`](crate::core::spc) — the six-command public `Spc` wrapper.
//!
//! The core layer holds no executor task, no buffer ownership and no profile
//! behaviour; buffers are re-borrowed by the caller on every poll.
//!
//! # Path ambiguity with the `core` crate
//!
//! This module is named `core`, so inside it always spell the language crate as
//! `::core::…`; a bare `core::…` in this tree risks resolving ambiguously.

pub mod async_wake;
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
pub mod slots;
pub mod spc;
pub mod storage;
pub mod target;
pub mod ua;

pub use self::async_wake::{wait, AsyncWake};
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
pub use self::runner::{DriveStep, PendingKind, RunEnd, RunOutcome, Runner};
pub use self::slots::{Job as SlotJob, SlotPool, SlotStore, SlotTask};
pub use self::spc::Spc;
pub use self::target::{StaticTarget, Target};
pub use self::ua::{ClearReason, ClearRule, Ua, UaClass, UaSet};
