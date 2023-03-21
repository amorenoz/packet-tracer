use anyhow::{bail, Result};
use plain::Plain;
use serde::{Deserialize, Serialize};

use crate::core::events::{
    bpf::{parse_raw_section, BpfRawSection},
    *,
};
use crate::{EventSection, EventSectionFactory};

// Tracking event section.
#[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
pub(crate) struct SkbTrackingEvent {
    pub(crate) orig_head: u64,
    pub(crate) timestamp: u64,
    pub(crate) skb: u64,
    pub(crate) drop_reason: Option<u32>,
}

impl RawEventSectionFactory for SkbTrackingEvent {
    fn from_raw(&mut self, mut raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        if raw_sections.len() != 1 {
            bail!("Skb tracking event from BPF must be a single section");
        }

        // Unwrap as we just checked the vector contains 1 element.
        let raw = parse_raw_section::<BpfTrackingEvent>(&raw_sections.pop().unwrap())?;

        let mut section = SkbTrackingEvent {
            orig_head: raw.orig_head,
            timestamp: raw.timestamp,
            skb: raw.skb,
            ..Default::default()
        };

        if raw.drop_reason >= 0 {
            section.drop_reason = Some(raw.drop_reason as u32);
        }

        Ok(Box::new(section))
    }
}

// Tracking event from BPF. Please keep in sync with its BPF counterpart.
#[derive(Default)]
#[repr(C, packed)]
struct BpfTrackingEvent {
    orig_head: u64,
    timestamp: u64,
    skb: u64,
    drop_reason: i32,
}

unsafe impl Plain for BpfTrackingEvent {}
