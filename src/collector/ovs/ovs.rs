use anyhow::{bail, Result};

use super::main_hook;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    collector::Collector,
    core::{
        events::bpf::BpfEvents,
        probe::{kernel, user, Hook},
    },
};

const OVS_COLLECTOR: &str = "ovs";

pub(in crate::collector) struct OvsCollector {}

impl Collector for OvsCollector {
    fn new() -> Result<OvsCollector> {
        Ok(OvsCollector {})
    }

    fn name(&self) -> &'static str {
        OVS_COLLECTOR
    }

    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        cmd.register_module_noargs(OVS_COLLECTOR)
    }

    fn init(
        &mut self,
        _: &CliConfig,
        _kernel: &mut kernel::Kernel,
        user: &mut user::User,
        _events: &mut BpfEvents,
    ) -> Result<()> {
        let ovs = user::Process::from_cmd("ovs-vswitchd")?;

        if let Some(usdt) = ovs.usdt_info() {
            if let Ok(false) = usdt.is_usdt("main::run_start") {
                bail!("USDTs not enabled on OVS");
            }
        }

        let main_probe = ovs.usdt_probe("main::run_start")?;
        user.register_hook_to(user::UProbe::Usdt(main_probe), Hook::from(main_hook::DATA))?;

        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
