use anyhow::{bail, Result};

use super::main_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collect::Collector,
    core::{
        events::bpf::BpfEvents,
        probe::{user::UsdtProbe, Hook, Probe, ProbeManager},
        user::proc::Process,
    },
    module::ModuleId,
};

pub(crate) struct OvsCollector {}

impl Collector for OvsCollector {
    fn new() -> Result<OvsCollector> {
        Ok(OvsCollector {})
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(ModuleId::Ovs.to_str())
    }

    fn init(
        &mut self,
        _: &CliConfig,
        probes: &mut ProbeManager,
        _events: &mut BpfEvents,
    ) -> Result<()> {
        let ovs = Process::from_cmd("ovs-vswitchd")?;

        if !ovs.is_usdt("main::run_start")? {
            bail!("main loop USDT not found");
        }

        let main_probe = Probe::Usdt(UsdtProbe::new(
            &ovs,
            "dpif_netlink_operate__::op_flow_execute",
        )?);
        probes.register_hook_to(Hook::from(main_hook::DATA), main_probe)?;

        Ok(())
    }
}
