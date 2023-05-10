use std::{
    collections::HashSet,
    fs,
    ops::Bound::{Included, Unbounded},
};

use anyhow::{anyhow, bail, Result};
use bimap::BiBTreeMap;
use log::warn;
use regex::Regex;

use super::btf::BtfInfo;
use crate::core::kernel::Symbol;

/// Provides helpers to inspect probe related information in the kernel.
pub(crate) struct KernelInspector {
    /// Btf information.
    pub(crate) btf: BtfInfo,
    /// Symbols bi-directional map (addr<>name).
    symbols: BiBTreeMap<u64, String>,
    /// Set of traceable events (e.g. tracepoints).
    traceable_events: Option<HashSet<String>>,
    /// Set of traceable functions (e.g. kprobes).
    traceable_funcs: Option<HashSet<String>>,
}

impl KernelInspector {
    pub(super) fn new() -> Result<KernelInspector> {
        let (symbols_file, events_file, funcs_file) = match cfg!(test) {
            false => (
                "/proc/kallsyms",
                "/sys/kernel/debug/tracing/available_events",
                "/sys/kernel/debug/tracing/available_filter_functions",
            ),
            true => (
                "test_data/kallsyms",
                "test_data/available_events",
                "test_data/available_filter_functions",
            ),
        };
        let btf = BtfInfo::new()?;

        // First parse the symbol file.
        let mut symbols = BiBTreeMap::new();
        // Lines have to be processed backward in order to overwrite
        // duplicate addresses and keep the first (which is the last
        // inserted in the common case involving module init
        // functions) instead of the last one.
        for line in fs::read_to_string(symbols_file)?.lines().rev() {
            let data: Vec<&str> = line.split(' ').collect();
            if data.len() < 3 {
                bail!("Invalid kallsyms line: {}", line);
            }

            let symbol: &str = data[2]
                .split('\t')
                .next()
                .ok_or_else(|| anyhow!("Couldn't get symbol name for {}", data[0]))?;

            symbols.insert(u64::from_str_radix(data[0], 16)?, String::from(symbol));
        }

        let inspector = KernelInspector {
            btf,
            symbols,
            // Not all events we'll get from BTF/kallsyms are traceable. Use the
            // following, when available, to narrow down our checks.
            traceable_events: Self::file_to_hashset(events_file),
            // Not all functions we'll get from BTF/kallsyms are traceable. Use
            // the following, when available, to narrow down our checks.
            traceable_funcs: Self::file_to_hashset(funcs_file),
        };

        if inspector.traceable_funcs.is_none() || inspector.traceable_events.is_none() {
            warn!(
                "Consider mounting debugfs to /sys/kernel/debug to better filter available probes"
            );
        }

        Ok(inspector)
    }

    /// Convert a file containing a list of str (one per line) into a HashSet.
    /// Returns None if the file can't be read.
    fn file_to_hashset(target: &str) -> Option<HashSet<String>> {
        if let Ok(file) = fs::read_to_string(target) {
            let mut set = HashSet::new();
            for line in file.lines() {
                // functions might be formatted as "func_name [module]".
                match line.to_string().split(' ').next() {
                    Some(symbol) => {
                        set.insert(symbol.to_string());
                    }
                    None => {
                        warn!("Symbol list element has an unexpected format in {target}: {line}");
                    }
                }
            }

            return Some(set);
        }
        None
    }

    /// Return a symbol name given its address, if a relationship is found.
    pub(crate) fn get_symbol_name(&self, addr: u64) -> Result<String> {
        Ok(self
            .symbols
            .get_by_left(&addr)
            .ok_or_else(|| anyhow!("Can't get symbol name for {}", addr))?
            .clone())
    }

    /// Return a symbol address given its name, if a relationship is found.
    pub(crate) fn get_symbol_addr(&self, name: &str) -> Result<u64> {
        Ok(*self
            .symbols
            .get_by_right(name)
            .ok_or_else(|| anyhow!("Can't get symbol address for {}", name))?)
    }

    /// Given an address, try to find the nearest symbol, if any.
    pub(crate) fn find_nearest_symbol(&self, target: u64) -> Result<u64> {
        let nearest = self
            .symbols
            .left_range((Unbounded, Included(&target)))
            .next_back();

        match nearest {
            Some(symbol) => Ok(*symbol.0),
            None => bail!("Can't get a symbol near {}", target),
        }
    }

    /// Check if an event is traceable. Return None if we can't know.
    pub(crate) fn is_event_traceable(&self, name: &str) -> Option<bool> {
        let set = &self.traceable_events;

        // If we can't check further, we don't know if the event is traceable and we
        // return None.
        if set.is_none() {
            return None;
        }

        // Unwrap as we checked above we have a set of valid events.
        Some(set.as_ref().unwrap().get(name).is_some())
    }

    /// Check if an event is traceable. Return None if we can't know.
    pub(crate) fn is_function_traceable(&self, name: &str) -> Option<bool> {
        let set = &self.traceable_funcs;

        // If we can't check further, we don't know if the function is traceable and
        // we return None.
        if set.is_none() {
            return None;
        }

        // Unwrap as we checked above we have a set of valid functions.
        Some(set.as_ref().unwrap().get(name).is_some())
    }

    /// Given an event name (without the group part), try to find a corresponding
    /// event (with the group part) and return the full name.
    ///
    /// `assert!(inspector().unwrap().find_matching_event("kfree_skb") == Some("skb:kfree_skb"));`
    pub(crate) fn find_matching_event(&self, name: &str) -> Option<String> {
        let set = &self.traceable_events;

        // If we can't check further, return None.
        if set.is_none() {
            return None;
        }

        let suffix = format!(":{name}");

        // Unwrap as we checked above we have a set of valid events.
        for event in set.as_ref().unwrap().iter() {
            if event.ends_with(&suffix) {
                return Some(event.clone());
            }
        }

        None
    }

    /// Get a parameter offset given a kernel function, if  any. Can be used to
    /// check a function has a given parameter by using:
    /// `inspector()?.parameter_offset()?.is_some()`
    pub(crate) fn parameter_offset(
        &self,
        symbol: &Symbol,
        parameter_type: &str,
    ) -> Result<Option<u32>> {
        self.btf.parameter_offset(symbol, parameter_type)
    }

    /// Get a function's number of arguments.
    pub(crate) fn function_nargs(&self, symbol: &Symbol) -> Result<u32> {
        self.btf.function_nargs(symbol)
    }

    /// Given an address, gets the name and the offset of the nearest symbol, if any.
    pub(crate) fn get_name_offt_from_addr_near(&self, addr: u64) -> Result<(String, u64)> {
        let sym_addr = self.find_nearest_symbol(addr)?;
        Ok((
            self.get_symbol_name(sym_addr)?,
            u64::checked_sub(addr, sym_addr)
                .ok_or_else(|| anyhow!("failed to get symbol offset"))?,
        ))
    }

    /// Find functions matching a given pattern. So far only wildcards (*) are
    /// supported, e.g. "tcp_v6_*".
    pub(crate) fn matching_functions(&self, target: &str) -> Result<Vec<String>> {
        let set = &self.traceable_funcs;

        if set.is_none() {
            bail!("Can't get matching functions, consider mounting /sys/kernel/debug");
        }

        let target = format!("^{}$", target.replace('*', ".*"));
        let re = Regex::new(&target)?;

        // Unwrap as we checked above we have a set of valid events.
        Ok(set
            .as_ref()
            .unwrap()
            .iter()
            .filter(|f| re.is_match(f))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::KernelInspector;

    fn inspector() -> KernelInspector {
        super::KernelInspector::new().unwrap()
    }

    #[test]
    fn inspector_init() {
        assert!(super::KernelInspector::new().is_ok());
    }

    #[test]
    fn symbol_name() {
        assert!(inspector().get_symbol_name(0xffffffff99d1da80).unwrap() == "consume_skb");
    }

    #[test]
    fn symbol_addr() {
        assert!(inspector().get_symbol_addr("consume_skb").unwrap() == 0xffffffff99d1da80);
    }

    #[test]
    fn test_bijection() {
        let symbol = "consume_skb";
        let addr = inspector().get_symbol_addr(symbol).unwrap();
        let name = inspector().get_symbol_name(addr).unwrap();

        assert!(symbol == name);
    }

    #[test]
    fn nearest_symbol() {
        let addr = inspector().get_symbol_addr("consume_skb").unwrap();

        assert!(inspector().find_nearest_symbol(addr + 1).unwrap() == addr);
        assert!(inspector().find_nearest_symbol(addr).unwrap() == addr);
        assert!(inspector().find_nearest_symbol(addr - 1).unwrap() != addr);
    }

    #[test]
    fn name_from_addr_near() {
        let mut sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80 + 1)
            .unwrap();

        assert_eq!(sym_info.0, "consume_skb");
        assert_eq!(sym_info.1, 0x1_u64);

        sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80 - 1)
            .unwrap();
        assert_ne!(sym_info.0, "consume_skb");

        sym_info = inspector()
            .get_name_offt_from_addr_near(0xffffffff99d1da80)
            .unwrap();
        assert_eq!(sym_info.0, "consume_skb");
        assert_eq!(sym_info.1, 0x0_u64);
    }
}
