//! Fixed slot collections: static `Cons`/`Nil` and runtime dyn slices.
//!
//! Two paths are kept: static `Cons` + type-level indices for embedded users,
//! and `&mut [&mut dyn Lu]` for runtime-sized/heterogeneous LUN tables. A
//! `Target` owns exactly one of them; the storage adapter is bound by the
//! application per LUN.

use ::core::marker::PhantomData;

use super::device::TargetId;
use super::lu::Lu;
use super::management::BoundaryReject;
use super::permit::OwnerBindPermit;
use super::runner::Runner;

/// Empty static slot list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nil;

/// Non-empty static slot list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cons<H, T> {
    /// First slot.
    pub head: H,
    /// Remaining slots.
    pub tail: T,
}

/// Build a `Cons` cell.
#[must_use]
pub const fn cons<H, T>(head: H, tail: T) -> Cons<H, T> {
    Cons { head, tail }
}

/// Type-level slot index: `Here` is 0, `There<...>` adds one.
pub trait Index {
    /// Runtime value of this type-level index.
    const INDEX: usize;
}

/// Index 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Here;

/// Index `I::INDEX + 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct There<I>(PhantomData<I>);

impl Index for Here {
    const INDEX: usize = 0;
}

impl<I: Index> Index for There<I> {
    const INDEX: usize = I::INDEX + 1;
}

/// Compile-time slot lookup. A missing index does not compile; there is no
/// runtime fallback.
pub trait At<I> {
    /// Slot selected by `I`.
    type Slot;

    /// Borrow the selected slot.
    fn slot(&self) -> &Self::Slot;

    /// Mutably borrow the selected slot.
    fn slot_mut(&mut self) -> &mut Self::Slot;
}

impl<H, T> At<Here> for Cons<H, T> {
    type Slot = H;

    fn slot(&self) -> &H {
        &self.head
    }

    fn slot_mut(&mut self) -> &mut H {
        &mut self.head
    }
}

impl<H, T, I> At<There<I>> for Cons<H, T>
where
    T: At<I>,
{
    type Slot = <T as At<I>>::Slot;

    fn slot(&self) -> &Self::Slot {
        self.tail.slot()
    }

    fn slot_mut(&mut self) -> &mut Self::Slot {
        self.tail.slot_mut()
    }
}

/// A fixed set of slots owned by a `Target`.
///
/// `bind_owner` is only callable with the crate-private [`OwnerBindPermit`],
/// so an application cannot rebind a slot after `Target::new`.
pub trait SlotSet {
    /// Fixed number of slots in this set.
    fn slot_count(&self) -> usize;

    /// Bind every slot to the owning target identity.
    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId);

    /// Control gate: check the authoritative boundary of every resident
    /// slot before a `Nop` control is queued. This is an internal extension of
    /// needed by `Target::request_control`; applications never call it.
    ///
    /// The default accepts (safe for an empty set); a custom `SlotSet` that
    /// owns resident slots must override it with the same conjunction.
    fn check_boundary(&self, _runner: &Runner) -> Result<(), BoundaryReject> {
        Ok(())
    }

    /// Management gate: no resident slot may hold an unclaimed result.
    ///
    /// [`Self::check_boundary`] covers the command/IO/long-operation boundary;
    /// a produced-but-unclaimed pair is the other half of "management may
    /// proceed". The default accepts (safe for an empty set); a custom
    /// `SlotSet` that owns resident slots must override it.
    fn check_result_absent(&self) -> Result<(), BoundaryReject> {
        Ok(())
    }
}

impl SlotSet for Nil {
    fn slot_count(&self) -> usize {
        0
    }

    fn bind_owner(&mut self, _permit: &OwnerBindPermit, _owner: TargetId) {}

    fn check_boundary(&self, _runner: &Runner) -> Result<(), BoundaryReject> {
        Ok(())
    }
}

impl<H: Lu, T: SlotSet> SlotSet for Cons<H, T> {
    fn slot_count(&self) -> usize {
        1 + self.tail.slot_count()
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        self.head.bind_owner(permit, owner);
        self.tail.bind_owner(permit, owner);
    }

    fn check_boundary(&self, runner: &Runner) -> Result<(), BoundaryReject> {
        runner.boundary::<H::Pair>(&self.head)?;
        self.tail.check_boundary(runner)
    }

    fn check_result_absent(&self) -> Result<(), BoundaryReject> {
        if self.head.has_result() {
            return Err(BoundaryReject::AwaitingResourceTake);
        }
        self.tail.check_result_absent()
    }
}

impl<P, const N: usize> SlotSet for [&mut dyn Lu<Pair = P>; N] {
    fn slot_count(&self) -> usize {
        N
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        for slot in self.iter_mut() {
            (**slot).bind_owner(permit, owner);
        }
    }

    fn check_boundary(&self, runner: &Runner) -> Result<(), BoundaryReject> {
        for slot in self.iter() {
            runner.boundary::<P>(&**slot)?;
        }
        Ok(())
    }

    fn check_result_absent(&self) -> Result<(), BoundaryReject> {
        for slot in self.iter() {
            if slot.has_result() {
                return Err(BoundaryReject::AwaitingResourceTake);
            }
        }
        Ok(())
    }
}

impl<P> SlotSet for &mut [&mut dyn Lu<Pair = P>] {
    fn slot_count(&self) -> usize {
        self.len()
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        for slot in self.iter_mut() {
            (**slot).bind_owner(permit, owner);
        }
    }

    fn check_boundary(&self, runner: &Runner) -> Result<(), BoundaryReject> {
        for slot in self.iter() {
            runner.boundary::<P>(&**slot)?;
        }
        Ok(())
    }

    fn check_result_absent(&self) -> Result<(), BoundaryReject> {
        for slot in self.iter() {
            if slot.has_result() {
                return Err(BoundaryReject::AwaitingResourceTake);
            }
        }
        Ok(())
    }
}

/// Runtime-sized, homogeneous-pair slot set (the CLI path).
///
/// Heterogeneous static `Cons` collections deliberately do **not** implement
/// this: their slots have different `Pair` types and must use static take.
pub trait RuntimeSet: SlotSet {
    /// Pair type shared by every slot.
    type Pair;

    /// Mutable access by runtime index.
    fn get<'s>(&'s mut self, index: usize) -> Option<&'s mut (dyn Lu<Pair = Self::Pair> + 's)>;

    /// Read-only projection by runtime index.
    #[allow(clippy::iter_nth)]
    fn get_ref<'s>(&'s self, index: usize) -> Option<&'s (dyn Lu<Pair = Self::Pair> + 's)>;
}

impl<P, const N: usize> RuntimeSet for [&mut dyn Lu<Pair = P>; N] {
    type Pair = P;

    fn get<'s>(&'s mut self, index: usize) -> Option<&'s mut (dyn Lu<Pair = P> + 's)> {
        self.get_mut(index)
            .map(|slot| &mut **slot as &mut (dyn Lu<Pair = P> + 's))
    }

    #[allow(clippy::iter_nth)]
    fn get_ref<'s>(&'s self, index: usize) -> Option<&'s (dyn Lu<Pair = P> + 's)> {
        self.iter()
            .nth(index)
            .map(|slot| &**slot as &(dyn Lu<Pair = P> + 's))
    }
}

impl<P> RuntimeSet for &mut [&mut dyn Lu<Pair = P>] {
    type Pair = P;

    fn get<'s>(&'s mut self, index: usize) -> Option<&'s mut (dyn Lu<Pair = P> + 's)> {
        self.get_mut(index)
            .map(|slot| &mut **slot as &mut (dyn Lu<Pair = P> + 's))
    }

    #[allow(clippy::iter_nth)]
    fn get_ref<'s>(&'s self, index: usize) -> Option<&'s (dyn Lu<Pair = P> + 's)> {
        self.iter()
            .nth(index)
            .map(|slot| &**slot as &(dyn Lu<Pair = P> + 's))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_values_are_type_level() {
        assert_eq!(Here::INDEX, 0);
        assert_eq!(There::<Here>::INDEX, 1);
        assert_eq!(There::<There::<Here>>::INDEX, 2);
    }

    #[test]
    fn cons_lookup_is_compile_time() {
        type Slots = Cons<u8, Cons<u16, Cons<u32, Nil>>>;
        let mut slots: Slots = cons(10u8, cons(20u16, cons(30u32, Nil)));
        assert_eq!(*<Slots as At<Here>>::slot(&slots), 10);
        assert_eq!(*<Slots as At<Here>>::slot_mut(&mut slots), 10);
        let tail = &slots.tail;
        assert_eq!(*<Cons<u16, Cons<u32, Nil>> as At<Here>>::slot(tail), 20);
        assert_eq!(
            *<Cons<u16, Cons<u32, Nil>> as At<There<Here>>>::slot(tail),
            30
        );
    }

    #[test]
    fn nil_is_empty() {
        assert_eq!(Nil.slot_count(), 0);
    }
}
