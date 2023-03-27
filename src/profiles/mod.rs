//! # Profiles
//!
//! Prototype: Profiles are rhai scripts that allow extending the CLI configuration.
//! TBD

// Re-export collector.rs
#[allow(clippy::module_inception)]
pub(crate) mod profiles;
#[allow(unused_imports)]
pub(crate) use profiles::*;

pub(crate) mod cli;
