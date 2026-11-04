//! Unit-attention classes and the fixed-size pending UA set.
//!
//! This module defines the vocabulary and the minimal merge/priority/clear
//! behaviour. The public [`Spc`](super::spc::Spc) wrapper owns the pending set:
//! it raises through `Device::raise_ua` (reached from
//! [`Target::raise_ua_rt`](super::target::Target::raise_ua_rt)) and reports /
//! consumes the highest-priority class on the next reporting command.

use super::errors::Sense;

/// The fixed unit-attention classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UaClass {
    /// Power-on or equivalent reset of the target epoch.
    PowerOn,
    /// Transport reset that could not preserve the nexus.
    BusReset,
    /// Explicit LU RESET task management function.
    LuReset,
    /// Nexus loss.
    NexusLoss,
    /// Generic medium change (not MMC-specific).
    MediumChanged,
    /// INQUIRY data actually changed.
    InquiryChanged,
    /// Dynamic LUN inventory change (never raised for a fixed LUN set).
    InventoryChanged,
}

/// What clears a pending unit attention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearRule {
    /// Consumed when reported via REQUEST SENSE / autosense.
    RequestSense,
    /// Only REPORT LUNS clears this class.
    ReportLuns,
}

/// An explicit clear request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearReason {
    /// REPORT LUNS: clears only inventory-change.
    ReportLuns,
    /// REQUEST SENSE / autosense consumption of the reported instance.
    RequestSense,
}

impl UaClass {
    /// All classes in priority order (lowest number reports first).
    pub const ALL: [UaClass; 7] = [
        UaClass::PowerOn,
        UaClass::BusReset,
        UaClass::LuReset,
        UaClass::NexusLoss,
        UaClass::MediumChanged,
        UaClass::InquiryChanged,
        UaClass::InventoryChanged,
    ];

    /// Fixed reporting priority; lower reports first.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            UaClass::PowerOn => 0,
            UaClass::BusReset => 1,
            UaClass::LuReset => 2,
            UaClass::NexusLoss => 3,
            UaClass::MediumChanged => 4,
            UaClass::InquiryChanged => 5,
            UaClass::InventoryChanged => 6,
        }
    }

    /// The fixed sense triple reported for this class.
    #[must_use]
    pub const fn sense(self) -> Sense {
        match self {
            UaClass::PowerOn => Sense::new(0x06, 0x29, 0x01),
            UaClass::BusReset => Sense::new(0x06, 0x29, 0x02),
            UaClass::LuReset => Sense::new(0x06, 0x29, 0x03),
            UaClass::NexusLoss => Sense::new(0x06, 0x29, 0x07),
            UaClass::MediumChanged => Sense::new(0x06, 0x28, 0x00),
            UaClass::InquiryChanged => Sense::new(0x06, 0x3F, 0x03),
            UaClass::InventoryChanged => Sense::new(0x06, 0x3F, 0x0E),
        }
    }

    /// Which clear path consumes this class.
    #[must_use]
    pub const fn clear_rule(self) -> ClearRule {
        match self {
            UaClass::InventoryChanged => ClearRule::ReportLuns,
            _ => ClearRule::RequestSense,
        }
    }

    /// Fixed slot index in [`UaSet`].
    const fn index(self) -> usize {
        match self {
            UaClass::PowerOn => 0,
            UaClass::BusReset => 1,
            UaClass::LuReset => 2,
            UaClass::NexusLoss => 3,
            UaClass::MediumChanged => 4,
            UaClass::InquiryChanged => 5,
            UaClass::InventoryChanged => 6,
        }
    }
}

/// One pending unit-attention instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ua {
    /// Class of this instance.
    pub class: UaClass,
    /// Fixed sense triple for the class.
    pub sense: Sense,
    /// Fixed reporting priority.
    pub priority: u8,
    /// Merge bookkeeping only (an epoch/target id in later cards). It never
    /// replaces an already-pending instance.
    pub merge_key: u8,
    /// Clear rule for this class.
    pub clear: ClearRule,
}

/// Fixed-size pending-UA set (one slot per class, no alloc, no history).
///
/// Same-class raises merge into the existing instance (the first one is kept,
/// later merge keys do not replace it). `peek`/`next` always choose the
/// highest-priority (lowest number) instance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UaSet {
    slots: [Option<Ua>; 7],
}

impl UaSet {
    /// Empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [None; 7] }
    }

    /// Number of pending instances.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut count = 0;
        let mut index = 0;
        while index < self.slots.len() {
            if self.slots[index].is_some() {
                count += 1;
            }
            index += 1;
        }
        count
    }

    /// Whether no unit attention is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Raise (or merge) a class. Returns `false` when an instance of this class
    /// is already pending; the existing instance is kept.
    pub fn raise(&mut self, class: UaClass, merge_key: u8) -> bool {
        let slot = class.index();
        if self.slots[slot].is_some() {
            return false;
        }
        self.slots[slot] = Some(Ua {
            class,
            sense: class.sense(),
            priority: class.priority(),
            merge_key,
            clear: class.clear_rule(),
        });
        true
    }

    /// Highest-priority pending instance, without consuming it.
    #[must_use]
    pub fn peek(&self) -> Option<Ua> {
        let mut best: Option<Ua> = None;
        let mut index = 0;
        while index < self.slots.len() {
            if let Some(ua) = self.slots[index] {
                if best.is_none_or(|current| ua.priority < current.priority) {
                    best = Some(ua);
                }
            }
            index += 1;
        }
        best
    }

    /// Report and consume the highest-priority instance that REQUEST SENSE /
    /// autosense may consume. `ReportLuns`-only classes are skipped and stay
    /// pending until REPORT LUNS.
    ///
    /// Not an `Iterator`: it skips `ReportLuns`-only classes, so it can return
    /// `None` while instances remain pending.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Ua> {
        let mut best: Option<Ua> = None;
        let mut index = 0;
        while index < self.slots.len() {
            if let Some(ua) = self.slots[index] {
                if ua.clear == ClearRule::RequestSense
                    && best.is_none_or(|current| ua.priority < current.priority)
                {
                    best = Some(ua);
                }
            }
            index += 1;
        }
        let best = best?;
        self.slots[best.class.index()] = None;
        Some(best)
    }

    /// Clear by the given reason. Returns how many instances were cleared.
    pub fn clear_by(&mut self, reason: ClearReason) -> usize {
        match reason {
            ClearReason::ReportLuns => usize::from(
                self.slots[UaClass::InventoryChanged.index()]
                    .take()
                    .is_some(),
            ),
            ClearReason::RequestSense => usize::from(self.next().is_some()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_class_merges_without_replacing() {
        let mut set = UaSet::new();
        assert!(set.is_empty());
        assert!(set.raise(UaClass::MediumChanged, 1));
        assert!(!set.raise(UaClass::MediumChanged, 2));
        assert_eq!(set.len(), 1);
        let pending = set.peek().expect("pending UA");
        assert_eq!(pending.class, UaClass::MediumChanged);
        assert_eq!(pending.merge_key, 1);
    }

    #[test]
    fn priority_order_is_fixed_and_observable() {
        let mut set = UaSet::new();
        assert!(set.raise(UaClass::InventoryChanged, 0));
        assert!(set.raise(UaClass::BusReset, 0));
        assert_eq!(set.len(), 2);
        assert_eq!(set.peek().expect("pending").class, UaClass::BusReset);

        let first = set.next().expect("request-sense UA");
        assert_eq!(first.class, UaClass::BusReset);
        assert_eq!(first.sense, Sense::new(0x06, 0x29, 0x02));

        // InventoryChanged is not consumed by REQUEST SENSE.
        assert_eq!(set.next(), None);
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.peek().expect("inventory still pending").class,
            UaClass::InventoryChanged
        );
    }

    #[test]
    fn report_luns_clears_only_inventory() {
        let mut set = UaSet::new();
        set.raise(UaClass::PowerOn, 0);
        set.raise(UaClass::InventoryChanged, 0);
        assert_eq!(set.clear_by(ClearReason::ReportLuns), 1);
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.peek().expect("power-on remains").class,
            UaClass::PowerOn
        );
        assert_eq!(set.clear_by(ClearReason::ReportLuns), 0);
    }

    #[test]
    fn request_sense_consumes_highest_priority() {
        let mut set = UaSet::new();
        set.raise(UaClass::MediumChanged, 0);
        set.raise(UaClass::PowerOn, 0);
        assert_eq!(set.clear_by(ClearReason::RequestSense), 1);
        assert_eq!(
            set.peek().expect("medium changed remains").class,
            UaClass::MediumChanged
        );
    }

    #[test]
    fn class_table_matches_protocol_document() {
        assert_eq!(UaClass::PowerOn.sense(), Sense::new(0x06, 0x29, 0x01));
        assert_eq!(
            UaClass::InventoryChanged.sense(),
            Sense::new(0x06, 0x3F, 0x0E)
        );
        assert_eq!(
            UaClass::InventoryChanged.clear_rule(),
            ClearRule::ReportLuns
        );
        assert_eq!(UaClass::PowerOn.clear_rule(), ClearRule::RequestSense);
        assert_eq!(UaClass::ALL.len(), 7);
        for (index, class) in UaClass::ALL.iter().enumerate() {
            assert_eq!(usize::from(class.priority()), index);
        }
    }
}
