//! # SkbCollector
//!
//! Provide a generic way to probe kernel functions and tracepoints (having a
//! `struct sk_buff *` as a parameter), to filter skbs, and to track them;
//! allowing to reconstruct their path in the Linux networking stack.

use anyhow::Result;

use super::Collector;
use crate::config::Cli;
use crate::core::probe::kernel;

pub(super) struct SkbCollector {}

impl Collector for SkbCollector {
    fn new() -> Result<SkbCollector> {
        Ok(SkbCollector {})
    }

    fn register_cli(&self, _: &mut Cli) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "skb"
    }

    fn init(&mut self, _kernel: &mut kernel::Kernel, _: &Cli) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}
