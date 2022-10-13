//! # Kprobe
//!
//! Module to handle attaching programs to kernel probes. The module is split
//! in two parts, the Rust code (here) and the eBPF one (bpf/kprobe.bpf.c and
//! its auto-generated part in bpf/out/).

use anyhow::{anyhow, bail, Result};

use super::*;

// TODO: use 'include!()' here when a new libbpf-cargo 0.13 is out.
#[path = "bpf/.out/kprobe.skel.rs"]
mod kprobe;
use kprobe::KprobeSkelBuilder;

#[derive(Default)]
pub(in crate::core::probe) struct KprobeBuilder {
    map: Vec<(String, i32)>,
    links: Vec<libbpf_rs::Link>,
}

impl ProbeBuilder for KprobeBuilder {
    fn new() -> KprobeBuilder {
        KprobeBuilder::default()
    }

    fn init(&mut self, map_fds: &Vec<(String, i32)>) -> Result<()> {
        if self.map.len() > 0 {
            bail!("Kprobe builder already initialized");
        }
        self.map = map_fds.clone();

        Ok(())
    }

    fn attach(&mut self, target: &str, hooks: &Vec<&'static [u8]>) -> Result<()> {
        let open_obj = KprobeSkelBuilder::default().open()?.obj;
        reuse_map_fds(&open_obj, &self.map)?;

        let mut obj = open_obj.load()?;

        let fd = obj
            .prog("probe_kprobe")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .fd();
        let mut links = freplace_hooks(fd, hooks)?;
        self.links.append(&mut links);

        self.links.push(
            obj.prog_mut("probe_kprobe")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_kprobe(false, target)?,
        );
        Ok(())
    }
}
