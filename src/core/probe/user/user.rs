#![allow(dead_code)] // FIXME

use std::{collections::HashMap, path::PathBuf};

use anyhow::{anyhow, bail, Result};

use super::usdt;
use crate::core::events::bpf::BpfEvents;
use crate::core::probe::common::Hook;

#[derive(Debug, PartialEq)]
pub struct UsdtProbe {
    /// The provider name.
    pub provider: String,
    /// The probe's name.
    pub name: String,
    /// The probe's symbol.
    pub ksym: u64,

    /// The target's path
    pub path: PathBuf,
    /// The target's pid
    pub pid: i32,
}

// TODO merge with kernel probes
/// Probes types supported by this crate.
#[derive(Debug, PartialEq)]
pub(crate) enum UProbe {
    Uprobe,
    Usdt(UsdtProbe),
    Max,
}

// This is a simplified version of kernel.::ProbeSet. We don't need that flexibility of mapping
// hooks and targets so a simpler struct can achieve the goal.
/// An EBPF program hooked to a userspace probe.
pub(crate) struct UserProgram {
    probe: UProbe,
    builder: Box<dyn UProbeBuilder>,
    hook: Hook,
}

/// Main object representing the kernel probes and providing an API for
/// consumers to register probes, hooks, maps, etc.
pub(crate) struct User {
    ///// Probes sets, one per probe type. Used to keep track of all non-specific
    ///// probes.
    //probes: [ProbeSet; UProbeType::Max as usize],

    // User only has targeted probes!
    progs: Vec<UserProgram>,
    maps: HashMap<String, i32>,
    //pub(crate) inspect: ProcInspector,???
}

impl User {
    pub(crate) fn new(events: &BpfEvents) -> Result<User> {
        let mut user = User {
            progs: Vec::new(),
            maps: HashMap::new(),
        };
        user.maps.insert("events_map".to_string(), events.map_fd());
        Ok(user)
    }

    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    pub(crate) fn register_hook_to(&mut self, probe: UProbe, hook: Hook) -> Result<()> {
        // Find if a hook has already been registered with this probe.
        if self.progs.iter().find(|u| u.probe == probe).is_some() {
            bail!("Hook already registered on this probe");
        }

        let builder = match probe {
            UProbe::Usdt(_) => Box::new(usdt::UsdtBuilder::new()),
            _ => bail!("Probe type not supported"),
        };

        self.progs.push(UserProgram {
            probe,
            builder,
            hook,
        });
        Ok(())
    }

    pub(crate) fn attach(&mut self) -> Result<()> {
        for prog in self.progs.iter_mut() {
            Self::attach_prog(prog, self.maps.clone())?;
        }
        Ok(())
    }

    pub(crate) fn attach_prog(prog: &mut UserProgram, maps: HashMap<String, i32>) -> Result<()> {
        let map_fds = maps.into_iter().collect();
        prog.builder.init(map_fds, prog.hook.clone())?;
        prog.builder.attach(&prog.probe)?;
        Ok(())
    }
}

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
pub(super) trait UProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(&mut self, map_fds: Vec<(String, i32)>, hook: Hook) -> Result<()>;
    /// Attach the  probe.
    fn attach(&mut self, probe: &UProbe) -> Result<()>;
}

// This is a complete copy of the one in kernel.rs. TODO: merge
pub(super) fn reuse_map_fds(
    open_obj: &libbpf_rs::OpenObject,
    map_fds: &[(String, i32)],
) -> Result<()> {
    for map in map_fds.iter() {
        open_obj
            .map(map.0.clone())
            .ok_or_else(|| anyhow!("Couldn't get map {}", map.0.clone()))?
            .reuse_fd(map.1)?;
    }
    Ok(())
}

// This is a very small variation of the one in kernel.rs. TODO: merge
/// Replace a hook in the program represented by it's fd
pub(super) fn replace_hook(fd: i32, hook: &Hook) -> Result<Vec<libbpf_rs::Link>> {
    let mut links = Vec::new();

    let target = "hook".to_string();

    let mut open_obj = libbpf_rs::ObjectBuilder::default().open_memory("hook", hook.bpf_prog)?;

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

    Ok(links)
}
