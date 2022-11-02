//! # OvsCollector
//!
//! Probe OpenvSwitch kernel probes and tracepoints (as well as USDT) and
//! understand what openvswitch does with a packet.

use anyhow::Result;

use super::Collector;
use crate::config::Cli;
use crate::core::probe::kernel;

pub(super) struct OvsCollector {
}

impl Collector for OvsCollector {
    fn new() -> Result<OvsCollector> {
        Ok(OvsCollector {})
    }

    fn register_cli(&self, cli: &mut Cli) -> Result<()> {
        cli.register_collector("ovs")?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ovs"
    }

    fn init(&mut self, _kernel: &mut kernel::Kernel, _: &Cli) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
