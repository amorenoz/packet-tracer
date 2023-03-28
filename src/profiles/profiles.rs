#![allow(dead_code)] // FIXME
use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Result};
use log::debug;
use rhai::{Engine, Scope, AST};

use crate::{
    cli::CliConfig,
    collect::cli::{Collect, CollectArgs},
    core::kernel::inspect,
};

/// Rai implementation of a Profile
pub(crate) struct Profile {
    engine: Engine,
    ast: AST,
}

impl Profile {
    pub fn load(path: PathBuf) -> Result<Profile> {
        let path = path.canonicalize()?;
        if !fs::metadata(&path)?.is_file() {
            bail!("Profile not found: {:?}", path)
        }

        let engine = Engine::new();
        let ast = engine
            .compile_file(path)
            .map_err(|e| anyhow!("Failed to compile profile {:?}", e))?;
        Ok(Profile { engine, ast })
        //FIXME: Run profile validation.
    }

    pub fn has_collect(&self) -> Result<bool> {
        Ok(self
            .ast
            .iter_functions()
            .find(|s| s.name == "collect")
            .is_some())
    }

    pub fn has_process(&self) -> Result<bool> {
        Ok(self
            .ast
            .iter_functions()
            .find(|s| s.name == "process")
            .is_some())
    }

    pub fn collect(&mut self, args: &mut CollectArgs) -> Result<()> {
        /// Main API for Collection Profiles
        #[derive(Default, Debug, Clone)]
        struct CollectProfile {
            collectors: Vec<String>,
            probes: Vec<String>,
        }

        impl CollectProfile {
            fn new() -> CollectProfile {
                CollectProfile::default()
            }
            fn add_collector(&mut self, collector: String) {
                // FIXME: We could make some checks here?
                self.collectors.push(collector);
            }
            fn add_probe(&mut self, probe: String) {
                // FIXME: We could make some checks here?
                self.probes.push(probe);
            }
        }

        // Functions to make available for symbol inspection. Enums are not supported so unwrapping
        // them.
        fn is_event_traceable(name: String) -> bool {
            inspect::is_event_traceable(name.as_str())
                .unwrap_or(Some(false))
                .unwrap_or(false)
        }
        fn is_function_traceable(name: String) -> bool {
            inspect::is_function_traceable(name.as_str())
                .unwrap_or(Some(false))
                .unwrap_or(false)
        }

        self.engine
            .register_type_with_name::<CollectProfile>("CollectProfile")
            .register_fn("collect_profile", CollectProfile::new)
            .register_fn("add_collector", CollectProfile::add_collector)
            .register_fn("add_probe", CollectProfile::add_probe)
            .register_fn("is_event_traceable", is_event_traceable)
            .register_fn("is_function_traceable", is_function_traceable);

        let mut scope = Scope::new();
        let mut collect = self
            .engine
            .call_fn::<CollectProfile>(&mut scope, &self.ast, "collect", ())
            .map_err(|e| anyhow!("Failure running profile collect configuration: {:?}", e))?;
        debug!("Processed profile with result {:#?}", collect);

        // Fill collectors and probes to main config
        for collector in collect.collectors.drain(..) {
            // FIXME: Handle duplicates
            args.collectors.push(collector);
        }
        // Fill collectors and probes to main config
        for probe in collect.probes.drain(..) {
            // FIXME: Handle duplicates
            args.probes.push(probe);
        }
        Ok(())
    }
}

pub(crate) fn enhance_collect(cli: &mut CliConfig) -> Result<()> {
    let collect = cli
        .subcommand
        .as_any_mut()
        .downcast_mut::<Collect>()
        .ok_or_else(|| anyhow!("wrong subcommand"))?;

    for path in &cli.main_config.profiles {
        // FIXME: Implement a name-based search over a well-known list of directories
        let mut profile = Profile::load(PathBuf::from(path))?;
        profile.collect(collect.args_mut()?)?;
    }
    Ok(())
}
