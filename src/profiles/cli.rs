//! # Profile
//!
//! Profiles is a CLI subcommand that allows listing and inspecting
//! profiles.

use anyhow::{anyhow, Result};
use std::{any::Any, path::Path};

use clap::error::Error as ClapError;
use clap::{command, ArgMatches, Args, Command, FromArgMatches, Subcommand};

use super::Profile;
use crate::cli::{CliConfig, SubCommand};

//FIXME: Change
const DEFAULT_PROFILES_PATH: &str = "test_data/profiles/";

// Doc comment
#[derive(Debug, Default, Subcommand)]
enum ProfileSubCommand {
    /// List profiles
    #[default]
    List,
}

#[derive(Args, Debug, Default)]
#[command(author, version, about, long_about)]
pub(crate) struct ProfileCmd {
    #[command(subcommand)]
    command: ProfileSubCommand,
}

impl SubCommand for ProfileCmd {
    fn new() -> Result<Self>
    where
        Self: Sized,
    {
        Ok(ProfileCmd::default())
    }

    fn name(&self) -> &'static str {
        "profile"
    }

    fn thin(&self) -> Result<Command> {
        Ok(Command::new("profile").about("Manage profiles"))
    }

    fn full(&self) -> Result<Command> {
        Ok(ProfileCmd::augment_args(
            Command::new("profile")
                .about("Manage profiles")
                .long_about("Manage profiles"),
        ))
    }

    /// Updates internal structures with clap's ArgMatches.
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError> {
        FromArgMatches::update_from_arg_matches(self, matches)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl ProfileCmd {
    pub(crate) fn run(&self, config: &CliConfig) -> Result<()> {
        let profile = config
            .subcommand
            .as_any()
            .downcast_ref::<ProfileCmd>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;
        match &profile.command {
            ProfileSubCommand::List => {
                for entry in Path::new(DEFAULT_PROFILES_PATH).read_dir()? {
                    let entry = entry?;
                    if let Ok(profile) = Profile::load(entry.path()) {
                        println!(
                            "{:?} -> Collects: {}. Process {}.",
                            entry.path(),
                            profile.has_collect()?,
                            profile.has_process()?
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
