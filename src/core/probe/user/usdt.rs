use anyhow::{anyhow, bail, Result};

use super::*;
use crate::core::probe::{get_ebpf_debug, Hook};

mod usdt_bpf {
    include!("bpf/.out/usdt.skel.rs");
}
use usdt_bpf::UsdtSkelBuilder;

#[derive(Default)]
pub(super) struct UsdtBuilder {
    obj: Option<libbpf_rs::Object>,
    links: Vec<libbpf_rs::Link>,
}

impl UProbeBuilder for UsdtBuilder {
    fn new() -> UsdtBuilder {
        UsdtBuilder::default()
    }

    fn init(&mut self, map_fds: Vec<(String, i32)>, hook: Hook) -> Result<()> {
        if self.obj.is_some() {
            bail!("Usdt Builder already initialized");
        }

        let mut skel = UsdtSkelBuilder::default();
        skel.obj_builder.debug(get_ebpf_debug());
        let mut skel = skel.open()?;

        let open_obj = skel.obj;
        reuse_map_fds(&open_obj, &map_fds)?;

        let obj = open_obj.load()?;
        let fd = obj
            .prog("probe_usdt")
            .ok_or_else(|| anyhow!("Couldn't get program"))?
            .fd();
        let mut links = replace_hook(fd, &hook)?;
        self.links.append(&mut links);

        self.obj = Some(obj);
        Ok(())
    }

    fn attach(&mut self, probe: &UProbe) -> Result<()> {
        let obj = match &mut self.obj {
            Some(obj) => obj,
            _ => bail!("USDT builder is uninitialized"),
        };

        let probe = match probe {
            UProbe::Usdt(ref usdt) => usdt,
            _ => bail!("Wrong probe type"),
        };

        self.links.push(
            obj.prog_mut("probe_usdt")
                .ok_or_else(|| anyhow!("Couldn't get program"))?
                .attach_usdt(
                    probe.pid,
                    probe.path.to_owned(),
                    probe.provider.to_owned().to_string(),
                    probe.name.to_owned().to_string(),
                )?,
        );
        Ok(())
    }
}
