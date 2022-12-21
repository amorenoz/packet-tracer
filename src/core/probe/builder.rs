//! # ProbeBuilder
//!
//! ProbeBuilder is able to build an attach eBPF programs to probes.
//!
//! The eBPF programs are essentially comprised of two elements:
//! - A scheleton that depends on the target type (e.g; kprobe, tp, etc).
//! - A number of hooks.
//!
//! To learn how hooks interact with the main program, see each individual
//! target type eBPF program.
//!
//! Additionally, ProbeBuilder supports sharing maps between programs.
//!
use anyhow::{anyhow, bail, Result};

use crate::core::probe::*;

// Kprobes:
mod kprobe_bpf {
    include!("kernel/bpf/.out/kprobe.skel.rs");
}
use kprobe_bpf::KprobeSkelBuilder;

// Raw tracepoints:
mod raw_tracepoint_bpf {
    include!("kernel/bpf/.out/raw_tracepoint.skel.rs");
}
use raw_tracepoint_bpf::RawTracepointSkelBuilder;

// USDT:
mod usdt_bpf {
    include!("user/bpf/.out/usdt.skel.rs");
}
use usdt_bpf::UsdtSkelBuilder;

#[derive(Default)]
pub(crate) struct ProbeBuilder {
    links: Vec<libbpf_rs::Link>,
    map_fds: Vec<(String, i32)>,
    hooks: Vec<Hook>,
}

impl ProbeBuilder {
    /// Creates a new ProbeBuilder
    pub(crate) fn new() -> ProbeBuilder {
        ProbeBuilder::default()
    }

    /// Intitializes the ProbeBuilder with a set of maps and hooks.
    pub(crate) fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<Hook>) -> Result<()> {
        self.map_fds = map_fds;
        self.hooks = hooks;
        Ok(())
    }

    /// Attaches a Probe.
    pub(crate) fn attach(&mut self, probe: &Probe) -> Result<()> {
        match probe {
            Probe::Kprobe(kprobe) => self.attach_kprobe(kprobe),
            Probe::RawTracepoint(tp) => self.attach_raw_tracepoint(tp),
            Probe::Usdt(usdt) => self.attach_usdt(usdt),
        }
    }

    fn attach_kprobe(&mut self, probe: &kernel::KernelProbe) -> Result<()> {
        let mut skel = KprobeSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;
        skel.rodata().nhooks = self.hooks.len() as u32;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;
        let mut links = replace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_kprobe(false, probe.symbol.attach_name())?);
        Ok(())
    }

    fn attach_raw_tracepoint(&mut self, probe: &kernel::KernelProbe) -> Result<()> {
        let mut skel = RawTracepointSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;

        skel.rodata().ksym = probe.ksym;
        skel.rodata().nargs = probe.nargs;
        skel.rodata().nhooks = self.hooks.len() as u32;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_raw_tracepoint")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        let mut links = replace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links
            .push(prog.attach_raw_tracepoint(probe.symbol.attach_name())?);
        Ok(())
    }

    fn attach_usdt(&mut self, probe: &user::UsdtProbe) -> Result<()> {
        let mut skel = UsdtSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let skel = skel.open()?;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &self.map_fds)?;

        let mut obj = open_obj.load()?;
        let prog = obj
            .prog_mut("probe_usdt")
            .ok_or_else(|| anyhow!("Couldn't get program"))?;

        if self.hooks.len() != 1 {
            bail!("USDT targets only support a single hook");
        }

        let mut links = replace_hooks(prog.fd(), &self.hooks)?;
        self.links.append(&mut links);

        self.links.push(prog.attach_usdt(
            probe.pid,
            &probe.path,
            probe.provider.to_owned(),
            probe.name.to_owned(),
        )?);
        Ok(())
    }
}

fn reuse_map_fds(open_obj: &libbpf_rs::OpenObject, map_fds: &[(String, i32)]) -> Result<()> {
    for map in map_fds.iter() {
        if let Some(open_map) = open_obj.map(map.0.clone()) {
            open_map.reuse_fd(map.1)?;
        } else {
            // This object does not have this particular map.
            continue
        }
    }
    Ok(())
}

fn replace_hooks(fd: i32, hooks: &[Hook]) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    for (i, hook) in hooks.iter().enumerate() {
        let target = format!("hook{}", i);

        let mut open_obj =
            libbpf_rs::ObjectBuilder::default().open_memory("hook", hook.bpf_prog)?;

        // We have to explicitly use a Vec below to avoid having an unknown size
        // at build time.
        let map_fds: Vec<(String, i32)> = hook.maps.clone().into_iter().collect();
        reuse_map_fds(&open_obj, &map_fds)?;

        let open_prog = open_obj
            .prog_mut("hook")
            .ok_or_else(|| anyhow!("Couldn't get hook program"))?;

        open_prog.set_prog_type(libbpf_rs::ProgramType::Ext);
        open_prog.set_attach_target(fd, Some(target))?;

        let mut obj = open_obj.load()?;
        links.push(
            obj.prog_mut("hook")
                .ok_or_else(|| anyhow!("Couldn't get hook program"))?
                .attach_trace()?,
        );
    }

    Ok(links)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::kernel::Symbol;
    use crate::core::probe::user::{proc::Process, UsdtProbe};

    use ::probe::probe as define_usdt;

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach_kprobes() {
        let mut builder = ProbeBuilder::new();

        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("kfree_skb_reason").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::kprobe(Symbol::from_name("consume_skb").unwrap()).unwrap())
            .is_ok());
    }

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach_tp() {
        let mut builder = ProbeBuilder::new();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::raw_tracepoint(Symbol::from_name("skb:kfree_skb").unwrap()).unwrap())
            .is_ok());
        assert!(builder
            .attach(&Probe::raw_tracepoint(Symbol::from_name("skb:consume_skb").unwrap()).unwrap())
            .is_ok());
    }

    #[test]
    #[cfg_attr(not(feature = "test_cap_bpf"), ignore)]
    fn init_and_attach_usdt() {
        define_usdt!(test_builder, usdt, 1);

        let mut builder = ProbeBuilder::new();

        let p = Process::from_pid(std::process::id() as i32).unwrap();

        // It's for now, the probes below won't do much.
        assert!(builder.init(Vec::new(), Vec::new()).is_ok());
        assert!(builder
            .attach(&Probe::Usdt(
                UsdtProbe::new(&p, "test_builder::usdt").unwrap()
            ))
            .is_ok());
    }
}
