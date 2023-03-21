use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::bpf::*;
use crate::core::events::{bpf::BpfRawSection, *};
use crate::{EventSection, EventSectionFactory};

/// Skb event section
/// TODO: unflatten
#[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
pub(crate) struct SkbEvent {
    // L2 fields
    pub(crate) etype: Option<u16>,
    pub(crate) src: Option<String>,
    pub(crate) dst: Option<String>,
    // IPv4 & IPv6 fields
    pub(crate) saddr: Option<String>,
    pub(crate) daddr: Option<String>,
    pub(crate) ip_version: Option<u8>,
    pub(crate) l3_len: Option<u16>,
    pub(crate) protocol: Option<u8>,
    // TCP & UDP fields
    pub(crate) sport: Option<u16>,
    pub(crate) dport: Option<u16>,
    // TCP fields
    pub(crate) tcp_seq: Option<u32>,
    pub(crate) tcp_ack_seq: Option<u32>,
    pub(crate) tcp_window: Option<u16>,
    pub(crate) tcp_flags: Option<u8>,
    // UDP fields
    pub(crate) udp_len: Option<u16>,
    // ICMP fields
    pub(crate) icmp_type: Option<u8>,
    pub(crate) icmp_code: Option<u8>,
    // Net device fields
    pub(crate) dev_name: Option<String>,
    pub(crate) ifindex: Option<u32>,
    pub(crate) rx_ifindex: Option<u32>,
    // Netns fields
    pub(crate) netns: Option<u32>,
    // Dataref fields
    pub(crate) cloned: Option<bool>,
    pub(crate) fclone: Option<bool>,
    pub(crate) users: Option<u8>,
    pub(crate) dataref: Option<u8>,
}

impl RawEventSectionFactory for SkbEvent {
    fn from_raw(&mut self, raw_sections: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
        let mut event = SkbEvent::default();

        for section in raw_sections.iter() {
            match section.header.data_type as u64 {
                SECTION_L2 => unmarshal_l2(section, &mut event),
                SECTION_IPV4 => unmarshal_ipv4(section, &mut event),
                SECTION_IPV6 => unmarshal_ipv6(section, &mut event),
                SECTION_TCP => unmarshal_tcp(section, &mut event),
                SECTION_UDP => unmarshal_udp(section, &mut event),
                SECTION_ICMP => unmarshal_icmp(section, &mut event),
                SECTION_DEV => unmarshal_dev(section, &mut event),
                SECTION_NS => unmarshal_ns(section, &mut event),
                SECTION_DATA_REF => unmarshal_data_ref(section, &mut event),
                _ => bail!("Unknown data type"),
            }?;
        }

        Ok(Box::new(event))
    }
}
