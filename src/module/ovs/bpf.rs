//! Rust<>BPF types definitions for the ovs module.
//! Please keep this file in sync with its BPF counterpart in bpf/.

use anyhow::{bail, Result};
use plain::Plain;

use crate::{
    core::events::{
        bpf::{parse_raw_section, BpfRawSection},
        EventField,
    },
    event_field,
};

/// Types of events that can be generated by the ovs module.
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) enum OvsEventType {
    /// Upcall tracepoint.
    Upcall = 0,
    /// Upcall received in userspace.
    RecvUpcall = 1,
    /// Flow Put Operation
    OpFlowPut = 2,
    /// Flow Exec Operation
    OpFlowExec = 3,
}

impl OvsEventType {
    pub(super) fn from_u8(val: u8) -> Result<OvsEventType> {
        use OvsEventType::*;
        let owner = match val {
            0 => Upcall,
            1 => RecvUpcall,
            2 => OpFlowPut,
            3 => OpFlowExec,
            x => bail!("Can't construct a OvsEventType from {}", x),
        };
        Ok(owner)
    }

    pub(super) fn to_str_ref(&self) -> Result<&str> {
        use OvsEventType::*;
        let ret = match self {
            Upcall => "upcall",
            RecvUpcall => "recv_upcall",
            OpFlowPut => "op_flow_put",
            OpFlowExec => "op_flow_exec",
        };
        Ok(ret)
    }
}

/// OVS Upcall data.
#[derive(Default)]
#[repr(C, packed)]
struct UpcallEvent {
    /// Upcall command. Holds OVS_PACKET_CMD:
    ///   OVS_PACKET_CMD_UNSPEC   = 0
    ///   OVS_PACKET_CMD_MISS     = 1
    ///   OVS_PACKET_CMD_ACTION   = 2
    ///   OVS_PACKET_CMD_EXECUTE  = 3
    cmd: u8,
    /// Upcall port.
    port: u32,
}
unsafe impl Plain for UpcallEvent {}

pub(super) fn unmarshall_upcall(raw: &BpfRawSection, fields: &mut Vec<EventField>) -> Result<()> {
    let event = parse_raw_section::<UpcallEvent>(raw)?;

    fields.push(event_field!("upcall_port", event.port));
    fields.push(event_field!("cmd", event.cmd));
    Ok(())
}

/// OVS Recv Upcall data.
#[derive(Default)]
#[repr(C, packed)]
struct RecvUpcall {
    r#type: u32,
    pkt_size: u32,
    key_size: u64,
}
unsafe impl Plain for RecvUpcall {}

pub(super) fn unmarshall_recv(raw: &BpfRawSection, fields: &mut Vec<EventField>) -> Result<()> {
    let event = parse_event::<RecvUpcall>(raw)?;

    fields.push(event_field!("upcall_type", event.r#type));
    fields.push(event_field!("pkt_size", event.pkt_size));
    fields.push(event_field!("key_size", event.key_size));
    Ok(())
}

/// OVS Operation Flow Put data.
#[derive(Default)]
#[repr(C, packed)]
struct OpFlowPut {
}
unsafe impl Plain for OpFlowPut {}

pub(super) fn unmarshall_op_put(raw: &BpfRawSection, fields: &mut Vec<EventField>) -> Result<()> {
    let event = parse_raw_section::<OpFlowPut>(raw)?;

    Ok(())
}


/// OVS Operation Flow Exec data.
#[derive(Default)]
#[repr(C, packed)]
struct OpFlowExec {
}
unsafe impl Plain for OpFlowExec {}

pub(super) fn unmarshall_op_exec(raw: &BpfRawSection, fields: &mut Vec<EventField>) -> Result<()> {
    let event = parse_raw_section::<OpFlowExec>(raw)?;

    Ok(())
}
