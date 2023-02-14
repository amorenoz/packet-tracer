//! # Fexit
//!
//! Module to handle attaching programs to kernel fexit probes.
//! The module is split in two parts, the Rust code (here) and the eBPF one
//! (bpf/fexit.bpf.c and its auto-generated part in bpf/.out/).

use anyhow::{anyhow, bail, Result};

use crate::core::probe::builder::*;
use crate::core::probe::*;

mod fexit_bpf {
    include!("bpf/.out/fexit.skel.rs");
}
use fexit_bpf::FexitSkelBuilder;

#[derive(Default)]
pub(crate) struct FexitBuilder {
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, i32)>,
    hooks: Vec<Hook>,
}

impl ProbeBuilder for FexitBuilder {
    fn new() -> FexitBuilder {
        FexitBuilder::default()
    }

    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        Ok(())
    }

    fn attach(&mut self, probe: &Probe) -> Result<()> {
        let mut skel = FexitSkelBuilder::default();
        //skel.obj_builder.debug(get_ebpf_debug());
        skel.obj_builder.debug(true);
        let mut skel = skel.open()?;

        let probe = match probe {
            Probe::Fexit(probe) => probe,
            _ => bail!("Wrong probe type {}", probe),
        };

        skel.rodata().ksym = probe.ksym;
        skel.rodata().nargs = probe.nargs;
        skel.rodata().nhooks = self.hooks.len() as u32;

        let mut open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;
        open_obj
            .prog_mut("probe_fexit")
            .ok_or_else(|| anyhow!("Could not get program"))?
            .set_attach_target(0, Some(probe.symbol.attach_name()))?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_fexit")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = replace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links.push(prog.attach()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::kernel::Symbol;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach() {
        let mut builder = FexitBuilder::new();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        println!(
            "{:?}",
            builder.attach(
                &Probe::fexit(Symbol::from_name("tcp_sendmsg").expect("symbol should exist"))
                    .expect("fexit creation")
            )
        );
        assert!(builder
            .attach(
                &Probe::fexit(Symbol::from_name("tcp_sendmsg").expect("symbol should exist"))
                    .expect("fexit creation")
            )
            .is_ok());
        assert!(builder
            .attach(
                &Probe::fexit(
                    Symbol::from_name("skb_send_sock_locked").expect("symbol should exist")
                )
                .expect("fexit creation")
            )
            .is_ok());
    }
}
