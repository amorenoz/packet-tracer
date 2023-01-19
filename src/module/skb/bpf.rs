//! Rust<>BPF types definitions for the SKB module. Fields are not translated in
//! the BPF part and can be represented in various orders, depending from where
//! they come from. Some handling might be needed in the unmarshalers.
//!
//! Please keep this file in sync with its BPF counterpart in bpf/skb_hook.bpf.c

use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
};

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
pub(super) const SECTION_IPV4: u64 = 1;
pub(super) const SECTION_IPV6: u64 = 2;
pub(super) const SECTION_TCP: u64 = 3;
pub(super) const SECTION_UDP: u64 = 4;
pub(super) const SECTION_ICMP: u64 = 5;

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

/// IPv4 data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIpv4Event {
    /// Source IP address. Stored in network order.
    src: u32,
    /// Destination IP address. Stored in network order.
    dst: u32,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for SkbIpv4Event {}

pub(super) fn unmarshal_ipv4(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbIpv4Event>(raw_section)?;

    let src = Ipv4Addr::from(u32::from_be(event.src));
    fields.push(event_field!("saddr", format!("{}", src)));
    let dst = Ipv4Addr::from(u32::from_be(event.dst));
    fields.push(event_field!("daddr", format!("{}", dst)));

    fields.push(event_field!("ip_version", 4));
    fields.push(event_field!("l3_len", u16::from_be(event.len)));
    fields.push(event_field!("protocol", event.protocol));

    Ok(())
}

/// IPv6 data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIpv6Event {
    /// Source IP address. Stored in network order.
    src: u128,
    /// Destination IP address. Stored in network order.
    dst: u128,
    /// IP packet length in bytes. Stored in network order.
    len: u16,
    /// L4 protocol.
    protocol: u8,
}
unsafe impl Plain for SkbIpv6Event {}

pub(super) fn unmarshal_ipv6(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbIpv6Event>(raw_section)?;

    let src = Ipv6Addr::from(u128::from_be(event.src));
    fields.push(event_field!("saddr", format!("{}", src)));
    let dst = Ipv6Addr::from(u128::from_be(event.dst));
    fields.push(event_field!("daddr", format!("{}", dst)));

    fields.push(event_field!("ip_version", 6));
    fields.push(event_field!("l3_len", u16::from_be(event.len)));
    fields.push(event_field!("protocol", event.protocol));

    Ok(())
}

/// TCP data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbTcpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Sequence number. Stored in network order.
    seq: u32,
    /// Ack sequence number. Stored in network order.
    ack_seq: u32,
    /// TCP window. Stored in network order.
    window: u16,
    /// TCP flags: fin, syn, rst, psh, ack, urg, ece, cwr.
    flags: u8,
    /// TCP data offset: size of the TCP header in 32-bit words.
    doff: u8,
}
unsafe impl Plain for SkbTcpEvent {}

impl SkbTcpEvent {
    fn fin(&self) -> u8 {
        self.flags & 1
    }
    fn syn(&self) -> u8 {
        (self.flags >> 1) & 1
    }
    fn rst(&self) -> u8 {
        (self.flags >> 2) & 1
    }
    fn psh(&self) -> u8 {
        (self.flags >> 3) & 1
    }
    fn ack(&self) -> u8 {
        (self.flags >> 4) & 1
    }
    fn urg(&self) -> u8 {
        (self.flags >> 5) & 1
    }
    fn ece(&self) -> u8 {
        (self.flags >> 6) & 1
    }
    fn cwr(&self) -> u8 {
        (self.flags >> 7) & 1
    }
}

pub(super) fn unmarshal_tcp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbTcpEvent>(raw_section)?;

    fields.push(event_field!("sport", u16::from_be(event.sport)));
    fields.push(event_field!("dport", u16::from_be(event.dport)));
    fields.push(event_field!("tcp_seq", u32::from_be(event.seq)));
    fields.push(event_field!("tcp_ack_seq", u32::from_be(event.ack_seq)));
    fields.push(event_field!("tcp_window", u16::from_be(event.window)));
    fields.push(event_field!("tcp_fin", event.fin()));
    fields.push(event_field!("tcp_syn", event.syn()));
    fields.push(event_field!("tcp_rst", event.rst()));
    fields.push(event_field!("tcp_psh", event.psh()));
    fields.push(event_field!("tcp_ack", event.ack()));
    fields.push(event_field!("tcp_urg", event.urg()));
    fields.push(event_field!("tcp_ece", event.ece()));
    fields.push(event_field!("tcp_cwr", event.cwr()));
    fields.push(event_field!("tcp_doff", event.doff));

    Ok(())
}

/// UDP data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbUdpEvent {
    /// Source port. Stored in network order.
    sport: u16,
    /// Destination port. Stored in network order.
    dport: u16,
    /// Lenght: length in bytes of the UDP header and UDP data. Stored in network order.
    len: u16,
}
unsafe impl Plain for SkbUdpEvent {}

pub(super) fn unmarshal_udp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbUdpEvent>(raw_section)?;

    fields.push(event_field!("sport", u16::from_be(event.sport)));
    fields.push(event_field!("dport", u16::from_be(event.dport)));
    fields.push(event_field!("udp_len", u16::from_be(event.len)));

    Ok(())
}

/// ICMP data retrieved from SKBs.
#[derive(Default)]
#[repr(C, packed)]
struct SkbIcmpEvent {
    /// ICMP type.
    r#type: u8,
    /// ICMP sub-type.
    code: u8,
}
unsafe impl Plain for SkbIcmpEvent {}

pub(super) fn unmarshal_icmp(
    raw_section: &BpfRawSection,
    fields: &mut Vec<EventField>,
) -> Result<()> {
    let event = parse_event::<SkbIcmpEvent>(raw_section)?;

    fields.push(event_field!("icmp_type", event.r#type));
    fields.push(event_field!("icmp_code", event.code));

    Ok(())
}
