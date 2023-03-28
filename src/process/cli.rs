//! # Process
//!
//! Process is a dnymaic CLI subcommand to allow importing events from a log
//! file and post-process them.

use std::{any::Any, path::PathBuf};

use anyhow::Result;
use clap::{error::Error as ClapError, ArgMatches, Args, Command, FromArgMatches};

use crate::cli::SubCommand;

#[derive(Args, Debug, Default)]
pub(crate) struct Process {
    #[arg(help = "Import events from the given file")]
    pub(super) file: PathBuf,
}

impl SubCommand for Process {
    fn new() -> Result<Self> {
        Ok(Process::default())
    }

    fn thin(&self) -> Result<Command> {
        Ok(Command::new("process").about("Post-process events"))
    }

    fn name(&self) -> &'static str {
        "process"
    }

    fn full(&self) -> Result<Command> {
        Ok(Process::augment_args(
            Command::new("process").about("Post-process events"),
        ))
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError> {
        <Self as FromArgMatches>::update_from_arg_matches(self, matches)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
