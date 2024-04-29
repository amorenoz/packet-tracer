use std::fmt;

use super::*;
use crate::event_section;

// Skb drop event section. Same as the event from BPF, please keep in sync with
// its BPF counterpart.
#[event_section("skb-drop")]
pub(crate) struct SkbDropEvent {
    /// Sub-system who generated the below drop reason. None for core reasons.
    pub(crate) subsys: Option<String>,
    /// Reason why a packet was freed/dropped. Only reported from specific
    /// functions. See `enum skb_drop_reason` in the kernel.
    pub(crate) drop_reason: String,
}

impl EventFmt for SkbDropEvent {
    fn event_fmt(&self, f: &mut fmt::Formatter, _: DisplayFormat) -> fmt::Result {
        match &self.subsys {
            None => write!(f, "drop (reason {})", self.drop_reason),
            Some(name) => write!(f, "drop (reason {name}/{})", self.drop_reason),
        }
    }
}