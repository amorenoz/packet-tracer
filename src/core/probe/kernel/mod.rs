//! # Kernel probes
//!
//! Module providing an API to attach probes in the Linux kernel, e.g. using
//! kprobes and raw tracepoints. The need to attach a probe in the kernel can
//! come from various sources (different collectors, the user, etc) and as such
//! some kind of synchronization and common logic is required; which is provided
//! here.

#![allow(dead_code)] // FIXME

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail, Result};
use log::info;

mod kprobe;
mod raw_tracepoint;

/// Probes types supported by this crate.
#[allow(dead_code)]
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum ProbeType {
    Kprobe,
    RawTracepoint,
    Max,
}

/// Main object representing the kernel probes and providing an API for
/// consumers to register probes, hooks, maps, etc.
pub(crate) struct Kernel {
    /// Probes sets, one per probe type. Used to keep track of all non-specific
    /// probes.
    probes: [ProbeSet; ProbeType::Max as usize],
    maps: HashMap<String, i32>,
}

struct ProbeSet {
    builder: Box<dyn ProbeBuilder>,
    targets: HashSet<String>,
}

impl ProbeSet {
    fn new(builder: Box<dyn ProbeBuilder>) -> ProbeSet {
        ProbeSet {
            builder,
            targets: HashSet::new(),
        }
    }
}

impl Kernel {
    pub(crate) fn new() -> Result<Kernel> {
        // Keep synced with the order of ProbeType!
        let probes: [ProbeSet; ProbeType::Max as usize] = [
            ProbeSet::new(Box::new(kprobe::KprobeBuilder::new())),
            ProbeSet::new(Box::new(raw_tracepoint::RawTracepointBuilder::new())),
        ];

        Ok(Kernel {
            probes,
            maps: HashMap::new(),
        })
    }

    /// Request to attach a probe of type r#type to a target identifier.
    ///
    /// ```
    /// kernel.add_probe(ProbeType::Kprobe, "kfree_skb_reason").unwrap();
    /// kernel.add_probe(ProbeType::RawTracepoint, "kfree_skb").unwrap();
    /// ```
    pub(crate) fn add_probe(&mut self, r#type: ProbeType, target: &str) -> Result<()> {
        let target = target.to_string();

        let set = &mut self.probes[r#type as usize];
        if !set.targets.contains(&target) {
            set.targets.insert(target);
        }

        Ok(())
    }

    /// Request to reuse a map fd. Useful for sharing maps across probes, for
    /// configuration, event reporting, or other use cases.
    ///
    /// ```
    /// kernel.reuse_map("config", fd).unwrap();
    /// ```
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        for set in self.probes.iter_mut() {
            if set.targets.is_empty() {
                continue;
            }

            // Initialize the probe builder, only once for all targets.
            let map_fds = self.maps.clone().into_iter().collect();
            set.builder.init(map_fds, Vec::new())?;

            // Attach a probe to all the targets in the set.
            for target in set.targets.iter() {
                info!("Attaching probe to {}", target);
                set.builder.attach(target)?;
            }
        }

        Ok(())
    }
}

/// Trait representing the interface used to create and handle probes. We use a
/// trait here as we're supporting various attach types.
trait ProbeBuilder {
    /// Allocate and return a new instance of the probe builder, with default
    /// values.
    fn new() -> Self
    where
        Self: Sized;
    /// Initialize the probe builder before attaching programs to probes. It
    /// takes an option vector of map fds so that maps can be reused and shared
    /// accross builders.
    fn init(&mut self, map_fds: Vec<(String, i32)>, hooks: Vec<&'static [u8]>) -> Result<()>;
    /// Attach a probe to a given target (function, tracepoint, etc).
    fn attach(&mut self, target: &str) -> Result<()>;
}

fn reuse_map_fds(open_obj: &libbpf_rs::OpenObject, map_fds: &Vec<(String, i32)>) -> Result<()> {
    if !map_fds.is_empty() {
        for map in map_fds {
            open_obj
                .map(map.0.clone())
                .ok_or_else(|| anyhow!("Couldn't get map {}", map.0.clone()))?
                .reuse_fd(map.1)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_probe() {
        let mut kernel = Kernel::new().unwrap();

        assert!(kernel
            .add_probe(ProbeType::Kprobe, "kfree_skb_reason")
            .is_ok());
        assert!(kernel.add_probe(ProbeType::Kprobe, "consume_skb").is_ok());
        assert!(kernel.add_probe(ProbeType::Kprobe, "consume_skb").is_ok());

        assert!(kernel
            .add_probe(ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());
        assert!(kernel
            .add_probe(ProbeType::RawTracepoint, "kfree_skb")
            .is_ok());
    }

    #[test]
    fn reuse_map() {
        let mut kernel = Kernel::new().unwrap();

        assert!(kernel.reuse_map("config", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_ok());
        assert!(kernel.reuse_map("event", 0).is_err());
    }
}
