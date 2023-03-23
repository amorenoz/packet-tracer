#![allow(dead_code)] // FIXME

use anyhow::{anyhow, Result};

use super::cli::Process;
use crate::{
    cli::CliConfig,
    core::events::file::FileEventsFactory,
    module::{get_modules, Group},
};

pub(crate) struct PostProcess {
    modules: Group,
    cli: CliConfig,
}

impl PostProcess {
    pub(crate) fn new(cli: CliConfig) -> Result<Self> {
        let config = cli
            .subcommand
            .as_any()
            .downcast_ref::<Process>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        let factory = FileEventsFactory::new(&config.file);
        let mut modules = get_modules(Box::new(factory))?;

        modules.start_factory()?;

        // Read all events from the factory.
        let mut events = Vec::new();
        while let Some(event) = modules.factory.next_event(None)? {
            events.push(event);
        }

        // Debug
        for event in events.iter() {
            println!("{}", event.to_json());
        }

        // Get one section and print one value
        if let Some(event) = events.get(0) {
            if let Some(skb) =
                event.get_section::<crate::module::skb::SkbEvent>(crate::module::ModuleId::Skb)
            {
                println!("event 0: skb.etype = {:?}", skb.etype);
            }
        }

        Ok(PostProcess { modules, cli })
    }
}
