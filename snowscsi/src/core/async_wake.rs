//! Waker-based completion seam for asynchronous shells (`no_std`, no runtime).
//!
//! The core is poll/step only: it never owns an executor, a waker or an
//! `async fn`. An asynchronous shell such as
//! `serve_async` (`crate::usb::serve`) owns the waker and awaits the storage
//! adapter through this trait, then feeds the next `Event` to the core.
//!
//! [`AsyncWake::poll_wake`] is the object-safe seam: an adapter registers the
//! caller's waker and reports whether progress is already available.
//! [`wait`] is a free convenience future for shells; it implies no runtime.
//!
//! # Adapter contract
//!
//! - **Slot ownership.** The platform adapter owns the slot table and mints
//!   [`IoToken`](super::storage::IoToken)s. The caller's `work`/`alt` banks may
//!   be registered as slots by the adapter; the core never learns where they
//!   live.
//! - **Zero copy for platform adapters.** A platform adapter may submit the
//!   caller's buffer directly to the hardware/DMA engine; it must not stage a
//!   private copy of the data. (A test adapter may instead use a safe deferred
//!   model that fills the buffer on completion.)
//! - **`poll_wake` never touches the caller's buffer.** It only registers a
//!   waker and inspects completion state. The buffer is re-borrowed by the core
//!   on the matching [`Storage::poll_exec`](super::storage::Storage::poll_exec)
//!   call.
//! - **Cancel settles before reuse.** A token whose operation was cancelled
//!   must be settled (and any in-flight hardware/DMA access stopped) before the
//!   adapter reuses the buffer or the slot; the runner only reuses a buffer
//!   after a `Ready` receipt or `cancel` returned.
//! - **`unsafe` stays in the platform adapter**, if the platform's DMA API
//!   requires it. This module and the core are `unsafe`-free.
//!
//! # Embassy flash adapter outline (not compiled)
//!
//! A concrete adapter lives in a platform crate and only implements the two
//! seams; this tree intentionally ships no flash driver.
//!
//! ```text
//! struct FlashStorage<'d> {
//!     flash: &'d mut Flash<'d>,           // platform flash peripheral
//!     jobs: [Option<Job>; 4],             // slot table owned by the adapter
//!     wake: AtomicWaker,                  // embassy-sync (or equivalent)
//! }
//!
//! impl Storage for FlashStorage<'_> {
//!     fn begin_exec(&mut self, req: IoReq) -> IoToken {
//!         let slot = self.free_slot()?;   // caller's buffer is not seen here
//!         self.submit(slot, req);         // lives in the slot table
//!         IoToken::new(slot, tag)
//!     }
//!     fn poll_exec(&mut self, token, buf) -> Poll<StorageReceipt> {
//!         // Re-borrow `buf`; DMA/flash reads write straight into it (no copy).
//!         self.poll_slot(token, buf)
//!     }
//!     fn cancel(&mut self, token) { self.settle(token); }
//! }
//!
//! impl AsyncWake for FlashStorage<'_> {
//!     fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
//!         // Register first, then check completion: no lost wake.
//!         self.wake.register(cx.waker());
//!         if self.jobs.iter().all(|job| job.is_settled()) {
//!             Poll::Ready(())
//!         } else {
//!             Poll::Pending
//!         }
//!     }
//! }
//!
//! // The flash interrupt / DMA completion callback calls `wake.wake()`.
//! // The shell does: on Action::StoragePending =>
//! //     async_wake::wait(storage).await; continue;
//! ```
//!
//! # Path ambiguity with the `core` crate
//!
//! This module lives inside `crate::core`, so the language crate is always
//! spelled `::core::…` here.

/// Register a waker and report whether the adapter has made progress.
///
/// The operation named by the adapter's live token is complete when this
/// returns [`Poll::Ready`]. A [`Poll::Pending`] result must have registered
/// `cx.waker()` (or an equivalent platform waker) so the adapter wakes it when
/// the operation settles.
pub trait AsyncWake {
    /// Register `cx`'s waker and report whether progress is available.
    fn poll_wake(&mut self, cx: &mut ::core::task::Context<'_>) -> ::core::task::Poll<()>;
}

/// Await one wake from `w`.
///
/// One call is one registration; a shell calls this again for every
/// `StoragePending` action. No runtime, timer or executor is implied.
pub async fn wait<W: AsyncWake + ?Sized>(w: &mut W) {
    ::core::future::poll_fn(|cx| w.poll_wake(cx)).await;
}
