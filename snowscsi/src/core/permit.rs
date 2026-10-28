//! Private-minting permits and the RAII execution borrow.
//!
//! Applications can never build a permit: every type here has private fields
//! and only crate-private minting entry points. `Target` mints
//! [`OwnerBindPermit`]; the `Runner` mints [`CommandPermit`]/[`BoundaryPermit`]
//! for its own target. Permits are compared by owner only; replace/remove/
//! eject/take never change target identity.

use ::core::cell::Cell;

use super::device::TargetId;

/// Proof that a slot may be bound to a `Target`. Minted privately by
/// `Target::new`; there is no public constructor.
#[derive(Clone, Copy, Debug)]
pub struct OwnerBindPermit {
    _private: (),
}

impl OwnerBindPermit {
    /// Crate-private minting entry point for `Target`.
    #[allow(dead_code)] // minted by `Target::new` in the target/runner card
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

/// Proof that a command-side entry is driven by the owning runner. Private
/// fields, no public constructor, `Copy`, no lifetime.
#[derive(Clone, Copy, Debug)]
pub struct CommandPermit {
    owner: TargetId,
}

impl CommandPermit {
    /// Crate-private minting entry point for the `Runner`.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) const fn new(owner: TargetId) -> Self {
        Self { owner }
    }

    /// The target identity this permit was stamped with.
    #[must_use]
    pub const fn owner(&self) -> TargetId {
        self.owner
    }
}

/// Proof that the runner checked the authoritative boundary for its own
/// target. Private fields, no public constructor, `Copy`, no lifetime.
#[derive(Clone, Copy, Debug)]
pub struct BoundaryPermit {
    owner: TargetId,
}

impl BoundaryPermit {
    /// Crate-private minting entry point for the `Runner`.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) const fn new(owner: TargetId) -> Self {
        Self { owner }
    }

    /// The target identity this permit was stamped with.
    #[must_use]
    pub const fn owner(&self) -> TargetId {
        self.owner
    }
}

/// RAII execution borrow over the runner's counter.
///
/// The flag is a **counter**, not a bool: nested windows must not clear each
/// other when the inner guard drops. Construction is crate-private (the runner
/// mints guards); `Drop` decrements.
pub struct ExecutionGuard<'a> {
    flag: &'a Cell<u32>,
}

impl<'a> ExecutionGuard<'a> {
    /// Crate-private minting entry point for `Runner::enter_execution_borrow`.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn new(flag: &'a Cell<u32>) -> Self {
        flag.set(flag.get().saturating_add(1));
        Self { flag }
    }

    /// Current nesting depth, for in-crate tests only.
    #[cfg(test)]
    fn count(&self) -> u32 {
        self.flag.get()
    }
}

impl Drop for ExecutionGuard<'_> {
    fn drop(&mut self) {
        self.flag.set(self.flag.get().saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_guard_counts_nested_borrows() {
        let flag = Cell::new(0u32);
        let outer = ExecutionGuard::new(&flag);
        assert_eq!(outer.count(), 1);
        {
            let inner = ExecutionGuard::new(&flag);
            assert_eq!(inner.count(), 2);
            assert_eq!(outer.count(), 2);
        }
        assert_eq!(outer.count(), 1);
        assert_eq!(flag.get(), 1);
        drop(outer);
        assert_eq!(flag.get(), 0);
    }

    #[test]
    fn permits_are_compared_by_owner() {
        let owner = TargetId::new(9);
        let command = CommandPermit::new(owner);
        let boundary = BoundaryPermit::new(owner);
        assert_eq!(command.owner(), owner);
        assert_eq!(boundary.owner(), owner);
        assert_eq!(
            BoundaryPermit::new(owner).owner(),
            CommandPermit::new(owner).owner()
        );
    }
}
