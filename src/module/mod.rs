//! # Module
//!
//! Modules are per-data/target implementations of data retrieval from kernel or
//! userspace events, specific helpers and post-processing logic.

// Re-export module.rs
#[allow(clippy::module_inception)]
pub(crate) mod module;
pub(crate) use module::*;

// Re-export group.rs
pub(crate) mod group;
pub(crate) use group::*;

pub(crate) mod ovs;
pub(crate) mod skb;
pub(crate) mod skb_tracking;
