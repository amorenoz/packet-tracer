//! Rust<>BPF types definitions for the SKB module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::mem;

use anyhow::{bail, Result};
use plain::Plain;

use crate::{
    core::events::{bpf::BpfRawSection, EventField},
    event_field,
};

/// Helper to check a raw section validity and parse it into a structured type.
fn parse_event<T>(raw_section: &BpfRawSection) -> Result<T>
where
    T: Default + Plain,
{
    if raw_section.data.len() != mem::size_of::<T>() {
        bail!("Section data is not the expected size");
    }

    let mut event = T::default();
    plain::copy_from_bytes(&mut event, &raw_section.data)
        .or_else(|_| bail!("Could not parse the raw section"))?;

    Ok(event)
}

/// Valid raw event sections of the skb collector. We do not use an enum here as
/// they are difficult to work with for bitfields and C repr conversion.
pub(super) const SECTION_L2: u64 = 0;

/// Global configuration passed down the BPF part.
#[repr(C, packed)]
pub(super) struct SkbConfig {
    /// Bitfield of what to collect from SKBs. Currently `1 << SECTION_x` is
    /// used to trigger retrieval of a given section.
    pub sections: u64,
}

/// L2 data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbL2Event {
    /// Source MAC address.
    src: [u8; 6],
    /// Destination MAC address.
    dst: [u8; 6],
    /// Ethertype. Stored in network order.
    etype: u16,
}
unsafe impl Plain for SkbL2Event {}

pub(super) fn unmarshal_l2(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbL2Event>(raw_section)?;

    fields.push(event_field!("etype", u16::from_be(event.etype)));
    fields.push(event_field!(
        "src",
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            event.src[0], event.src[1], event.src[2], event.src[3], event.src[4], event.src[5],
        )
    ));
    fields.push(event_field!(
        "dst",
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            event.dst[0], event.dst[1], event.dst[2], event.dst[3], event.dst[4], event.dst[5],
        )
    ));

    Ok(())
}
