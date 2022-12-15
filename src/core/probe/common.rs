//! # Common
//!
//! Module providing infrastructure shared by all probes

use anyhow::{bail, Result};
use std::collections::HashMap;

use once_cell::sync::OnceCell;

static EBPF_DEBUG: OnceCell<bool> = OnceCell::new();

/// Sets global ebpf debug flag.
///
/// It must only be set once.
/// It will return Ok if it's the first time the it's been set or Err if it was already set.
pub(crate) fn set_ebpf_debug(debug: bool) -> Result<()> {
    EBPF_DEBUG
        .set(debug)
        .or_else(|_| bail!("ebpf_debug was already set"))?;
    Ok(())
}

/// Returns the current value of the global ebpf debug flag.
///
/// If called before [`set_ebpf_debug`] has been called, it will be set to false.
pub(crate) fn get_ebpf_debug() -> bool {
    // Always debug when running tests.
    if cfg!(test) {
        true
    } else {
        *EBPF_DEBUG.get_or_init(|| false)
    }
}

// Copied from kernel.rs: TODO: merge in a better place
/// Hook provided by modules for registering them on kernel probes.
#[derive(Clone)]
pub(crate) struct Hook {
    /// Hook BPF binary data.
    pub bpf_prog: &'static [u8],
    /// HashMap of maps names and their fd, for reuse by the hook.
    pub maps: HashMap<String, i32>,
}

impl Hook {
    /// Create a new hook given a BPF binary data.
    pub(crate) fn from(bpf_prog: &'static [u8]) -> Hook {
        Hook {
            bpf_prog,
            maps: HashMap::new(),
        }
    }

    /// Request to reuse a map specifically in the hook. For maps being globally
    /// reused please use User::reuse_map() instead.
    pub(crate) fn reuse_map(&mut self, name: &str, fd: i32) -> Result<&mut Self> {
        let name = name.to_string();

        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(self)
    }
}
