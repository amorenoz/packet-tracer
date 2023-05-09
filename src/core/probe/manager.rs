#![allow(dead_code)] // FIXME
use std::collections::HashMap;

use anyhow::{bail, Result};
use log::{debug, info};

#[cfg(not(test))]
use super::kernel::config::init_config_map;
use super::*;
use super::{
    builder::ProbeBuilder,
    kernel::{kprobe, kretprobe, raw_tracepoint},
    user::usdt,
};
use crate::core::filters::Filter;

// Keep in sync with their BPF counterparts in bpf/include/common.h
pub(crate) const PROBE_MAX: usize = 1024;
pub(super) const HOOK_MAX: usize = 10;

/// ProbeManager is the main object providing an API for consumers to register probes, hooks, maps,
/// etc.
pub(crate) struct ProbeManager {
    /// All generic probes.
    generic_probes: HashMap<String, Probe>,

    /// Generic hooks, meant to be attached to all probes supporting it..
    generic_hooks: Vec<Hook>,

    /// Filters, meant to be attached to all probes.
    filters: Vec<Filter>,

    /// Targeted sets, for hooks requesting to be specifically attached to a set
    /// of probes. Those might also support generic hooks.
    targeted_probes: Vec<ProbeSet>,

    /// List of global probe options to enable/disable additional probes behavior at a high level.
    global_probes_options: Vec<ProbeOption>,

    /// HashMap of map names and file descriptors, to be reused in all hooks.
    maps: HashMap<String, i32>,

    /// Dynamic probes requires a map that provides extra information at runtime. This is that map.
    #[cfg(not(test))]
    config_map: libbpf_rs::Map,

    /// Internal vec to store "used" probe builders, so we can keep a reference
    /// on them and keep probes loaded & installed.
    // TODO: should we change the builders to return the libbpf_rs::Link
    // directly?
    builders: Vec<Box<dyn ProbeBuilder>>,
}

impl ProbeManager {
    pub(crate) fn new() -> Result<ProbeManager> {
        // When testing the kernel object is not modified later to reuse the
        // config map is this map is hidden.
        #[allow(unused_mut)]
        let mut mgr = ProbeManager {
            generic_probes: HashMap::new(),
            generic_hooks: Vec::new(),
            filters: Vec::new(),
            targeted_probes: Vec::new(),
            global_probes_options: Vec::new(),
            maps: HashMap::new(),
            #[cfg(not(test))]
            config_map: init_config_map()?,
            builders: Vec::new(),
        };

        #[cfg(not(test))]
        mgr.maps
            .insert("config_map".to_string(), mgr.config_map.fd());

        Ok(mgr)
    }

    /// Set a probe option for later fixup during the attach phase. A given
    /// option can only be set once as those are global and we can't decide
    /// which version to keep.
    pub(crate) fn set_probe_opt(&mut self, opt: ProbeOption) -> Result<()> {
        if self
            .global_probes_options
            .iter()
            .any(|o| std::mem::discriminant(o) == std::mem::discriminant(&opt))
        {
            bail!("Option is already set");
        }

        self.global_probes_options.push(opt);
        Ok(())
    }

    /// Request to attach a dynamic probe to `Probe`.
    ///
    /// ```
    /// let symbol = kernel::Symbol::from_name("kfree_skb_reason").unwrap();
    /// mgr.add_probe(Probe::kprobe(symbol).unwrap()).unwrap();
    ///
    /// let symbol = kernel::Symbol::from_name("skb:kfree_skb").unwrap();
    /// mgr.add_probe(Probe::raw_tracepoint(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn add_probe(&mut self, probe: Probe) -> Result<()> {
        let key = probe.key();

        // Check if it is already in the targeted probe list.
        for set in self.targeted_probes.iter() {
            if set.probes.contains_key(&key) {
                return Ok(());
            }
        }

        self.check_probe_max()?;

        // If not, insert it in the generic probe list, if not there already.
        self.generic_probes.entry(key).or_insert(probe);

        Ok(())
    }

    /// Request to reuse a map fd. Useful for sharing maps across probes, for
    /// configuration, event reporting, or other use cases.
    ///
    /// ```
    /// mgr.reuse_map("config", fd).unwrap();
    /// ```
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    /// Request a filter to be attached to all probes.
    ///
    /// ```
    /// mgr.register_filter(filter)?;
    /// ```
    pub(crate) fn register_filter(&mut self, filter: Filter) -> Result<()> {
        // Avoid duplicate filter types as any Filter variant should
        // be present only once
        if self
            .filters
            .iter()
            .any(|f| std::mem::discriminant(f) == std::mem::discriminant(&filter))
        {
            bail!("Tried to register multiple filters of the same type");
        }

        self.filters.push(filter);
        Ok(())
    }

    /// Request a hook to be attached to all kernel probes.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// mgr.register_kernel_hook(Hook::from(hook::DATA))?;
    /// ```
    pub(crate) fn register_kernel_hook(&mut self, hook: Hook) -> Result<()> {
        let mut max: usize = 0;
        self.targeted_probes.iter_mut().for_each(|set| {
            if max < set.hooks.len() {
                max = set.hooks.len();
            }
        });

        if self.generic_hooks.len() + max >= HOOK_MAX {
            bail!("Hook list is already full");
        }

        self.generic_hooks.push(hook);
        Ok(())
    }

    /// Request a hook to be attached to a specific `Probe`.
    ///
    /// ```
    /// mod hook {
    ///     include!("bpf/.out/hook.rs");
    /// }
    ///
    /// [...]
    ///
    /// let symbol = kernel::Symbol::from_name("kfree_skb_reason").unwrap();
    /// mgr.register_hook_to(hook::DATA, Probe::kprobe(symbol).unwrap()).unwrap();
    /// ```
    pub(crate) fn register_hook_to(&mut self, hook: Hook, probe: Probe) -> Result<()> {
        if self.generic_hooks.len() >= HOOK_MAX {
            bail!("Hook list is already full");
        }

        let key = probe.key();

        // First check if the target isn't already registered to the generic
        // probes list. If so, remove it from there.
        self.generic_probes.remove(&key);

        // Now check if we already have a targeted probe for this. If so, append
        // the new hook to it.
        for set in self.targeted_probes.iter_mut() {
            if set.probes.contains_key(&key) {
                if let Probe::Usdt(_) = probe {
                    bail!("USDT probes only support a single hook");
                }

                if self.generic_hooks.len() + set.hooks.len() >= HOOK_MAX {
                    bail!("Hook list is already full");
                }

                set.hooks.push(hook);
                return Ok(());
            }
        }

        self.check_probe_max()?;

        // New target, let's build a new probe set.
        let mut set = ProbeSet {
            supports_generic_hooks: match &probe {
                Probe::Kprobe(_) | Probe::Kretprobe(_) | Probe::RawTracepoint(_) => true,
                Probe::Usdt(_) => false,
            },
            ..Default::default()
        };
        set.probes.insert(key, probe);
        set.hooks.push(hook);

        self.targeted_probes.push(set);
        Ok(())
    }

    /// Attach all probes.
    pub(crate) fn attach(&mut self) -> Result<()> {
        let mut attached = self.generic_probes.len();

        // First, handle generic probes.
        let mut set = ProbeSet {
            probes: self.generic_probes.clone(),
            hooks: self.generic_hooks.clone(),
            supports_generic_hooks: true,
        };
        self.builders.extend(set.attach(
            &self.filters,
            #[cfg(not(test))]
            &mut self.config_map,
            self.maps.clone(),
            #[cfg(not(test))]
            &self.global_probes_options,
        )?);

        // Then targeted ones.
        self.targeted_probes
            .iter_mut()
            .try_for_each(|set| -> Result<()> {
                attached += set.probes.len();
                if set.supports_generic_hooks {
                    set.hooks.extend(self.generic_hooks.clone());
                }
                self.builders.extend(set.attach(
                    &self.filters,
                    #[cfg(not(test))]
                    &mut self.config_map,
                    self.maps.clone(),
                    #[cfg(not(test))]
                    &self.global_probes_options,
                )?);
                Ok(())
            })?;

        // All probes loaded, issue an info log.
        info!("{} probe(s) loaded", attached);

        Ok(())
    }

    fn check_probe_max(&self) -> Result<()> {
        let mut size: usize = self.generic_probes.len();
        self.targeted_probes
            .iter()
            .for_each(|set| size += set.probes.len());

        if size >= PROBE_MAX {
            bail!(
                "Can't register probe, reached maximum capacity ({})",
                PROBE_MAX
            );
        }

        Ok(())
    }
}

#[derive(Default)]
struct ProbeSet {
    probes: HashMap<String, Probe>,
    hooks: Vec<Hook>,
    supports_generic_hooks: bool,
}

impl ProbeSet {
    /// Attach all the probes and hook in the ProbeSet.
    fn attach(
        &mut self,
        filters: &[Filter],
        #[cfg(not(test))] config_map: &mut libbpf_rs::Map,
        maps: HashMap<String, i32>,
        #[cfg(not(test))] options: &[ProbeOption],
    ) -> Result<Vec<Box<dyn ProbeBuilder>>> {
        if self.probes.is_empty() {
            debug!("No probe in probe set");
            return Ok(Vec::new());
        }

        let mut builders: HashMap<usize, Box<dyn ProbeBuilder>> = HashMap::new();
        let map_fds: Vec<(String, i32)> = maps.into_iter().collect();

        self.probes.iter_mut().try_for_each(|(_, probe)| {
            // Make a new builder if none if found for the current type. Builder
            // are shared for all probes of the same type within this set.
            match builders.contains_key(&probe.type_key()) {
                false => {
                    let mut builder: Box<dyn ProbeBuilder> = match probe {
                        Probe::Kprobe(_) => Box::new(kprobe::KprobeBuilder::new()),
                        Probe::Kretprobe(_) => Box::new(kretprobe::KretprobeBuilder::new()),
                        Probe::RawTracepoint(_) => {
                            Box::new(raw_tracepoint::RawTracepointBuilder::new())
                        }
                        Probe::Usdt(_) => Box::new(usdt::UsdtBuilder::new()),
                    };

                    // Initialize the probe builder, only once for all targets.
                    builder.init(map_fds.clone(), self.hooks.clone(), filters.to_owned())?;

                    builders.insert(probe.type_key(), builder);
                }
                true => (),
            }
            // Unwrap as we just made sure the probe builder would be available.
            let builder = builders.get_mut(&probe.type_key()).unwrap();

            // First load the probe configuration.
            #[cfg(not(test))]
            match probe {
                Probe::Kprobe(ref mut p)
                | Probe::Kretprobe(ref mut p)
                | Probe::RawTracepoint(ref mut p) => {
                    options.iter().try_for_each(|c| p.set_option(c))?;
                    let config = unsafe { plain::as_bytes(&p.config) };
                    config_map.update(&p.ksym.to_ne_bytes(), config, libbpf_rs::MapFlags::ANY)?;
                }
                _ => (),
            }

            // Finally attach a probe to the target.
            debug!("Attaching probe to {}", probe);
            builder.attach(probe)
        })?;

        Ok(builders.drain().map(|(_, v)| v).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::kernel::Symbol;

    // Dummy hook.
    const HOOK: &[u8] = &[0];

    macro_rules! kprobe {
        ($target:literal) => {
            Probe::kprobe(Symbol::from_name($target).unwrap()).unwrap()
        };
    }

    macro_rules! raw_tp {
        ($target:literal) => {
            Probe::raw_tracepoint(Symbol::from_name($target).unwrap()).unwrap()
        };
    }

    #[test]
    fn add_probe() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());
        assert!(mgr.add_probe(kprobe!("consume_skb")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
    }

    #[test]
    fn register_hooks() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());

        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());
        assert!(mgr.add_probe(kprobe!("kfree_skb_reason")).is_ok());

        assert!(mgr.add_probe(raw_tp!("skb:kfree_skb")).is_ok());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_ok());

        for _ in 0..HOOK_MAX - 4 {
            assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_ok());
        }

        // We should hit the hook limit here.
        assert!(mgr.register_kernel_hook(Hook::from(HOOK)).is_err());

        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_ok());

        // We should hit the hook limit here as well.
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), kprobe!("kfree_skb_reason"))
            .is_err());
        assert!(mgr
            .register_hook_to(Hook::from(HOOK), raw_tp!("skb:kfree_skb"))
            .is_err());
    }

    #[test]
    fn reuse_map() {
        let mut mgr = ProbeManager::new().unwrap();

        assert!(mgr.reuse_map("config", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_ok());
        assert!(mgr.reuse_map("event", 0).is_err());
    }
}
