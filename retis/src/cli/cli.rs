//! # Cli
//!
//! Cli module, providing tools for registering and accessing command line interface arguments
//! as well as defining the subcommands that the tool supports.
#![allow(dead_code)] // FIXME
use std::{
    any::Any, convert::From, env, ffi::OsString, fmt::Debug, path::PathBuf, str::FromStr, sync::Arc,
};

use anyhow::{anyhow, bail, Result};
use clap::{
    builder::PossibleValuesParser,
    error::Error as ClapError,
    error::ErrorKind,
    {ArgMatches, Args, Command, FromArgMatches, ValueEnum},
};
use log::{debug, LevelFilter};

#[cfg(feature = "benchmark")]
use crate::benchmark::cli::Benchmark;
use crate::{
    collect::cli::Collect,
    generate::Complete,
    helpers::logger::{set_libbpf_rs_print_callback, Logger},
    inspect::Inspect,
    process::cli::*,
    profiles::{cli::ProfileCmd, Profile},
};

/// SubCommandRunner defines the common interface to run SubCommands.
pub(crate) trait SubCommandRunner {
    /// Run the subcommand with a given set of modules and cli configuration
    fn run(&mut self, cli: CliConfig) -> Result<()>;
}

/// SubCommandRunnerFunc is a wrapper for functions that implements SubCommandRunner
pub(crate) struct SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    func: F,
}

impl<F> SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    pub(crate) fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> SubCommandRunner for SubCommandRunnerFunc<F>
where
    F: Fn(CliConfig) -> Result<()>,
{
    fn run(&mut self, cli: CliConfig) -> Result<()> {
        (self.func)(cli)
    }
}

/// SubCommand defines the way to handle SubCommands.
/// SubCommands provides a convenient way of encapsulating both the arguments of a subcommand
/// (i.e: clap::Command) and a way to run it (provided by SubCommandRunner)
pub(crate) trait SubCommand {
    /// Allocate and return a new instance of a SubCommand.
    fn new() -> Result<Self>
    where
        Self: Sized;

    /// Returns the unique name of the subcommand.
    fn name(&self) -> String;

    /// Returns self as a std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any(&self) -> &dyn Any;

    /// Returns self as a mutable std::any::Any trait.
    ///
    /// This is useful for dynamically downcast the SubCommand into it's specific type to access
    /// subcommand-specific functionality.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Generate the clap Command.
    fn command(&mut self) -> Result<Command>;

    /// Updates internal structures with clap's ArgMatches.
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), ClapError>;

    /// Return a SubCommandRunner capable of running this command.
    fn runner(&self) -> Result<Box<dyn SubCommandRunner>>;
}

impl Debug for dyn SubCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubCommand ({})", self.name())
    }
}

/// Trait to convert a clap::Parser into a SubCommandRunner.
pub(crate) trait SubCommandParserRunner: clap::Parser + Default {
    fn run(&mut self) -> Result<()>;
}

// Default implementation of SubCommand for all SubCommandParserRunner.
// This makes it much easier to implement small and easy subcommands without much boilerplate.
impl<F> SubCommand for F
where
    F: SubCommandParserRunner + 'static,
{
    fn new() -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::default())
    }

    fn name(&self) -> String {
        <Self as clap::CommandFactory>::command()
            .get_name()
            .to_string()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn command(&mut self) -> Result<Command> {
        Ok(<Self as clap::CommandFactory>::command())
    }

    fn update_from_arg_matches(&mut self, args: &ArgMatches) -> Result<(), ClapError> {
        <Self as clap::FromArgMatches>::update_from_arg_matches(self, args)
    }

    fn runner(&self) -> Result<Box<dyn SubCommandRunner>> {
        Ok(Box::new(SubCommandRunnerFunc::new(
            |mut cli: CliConfig| -> Result<()> {
                let cmd: &mut Self = cli
                    .subcommand
                    .as_any_mut()
                    .downcast_mut::<Self>()
                    .ok_or_else(|| anyhow!("wrong subcommand"))?;
                cmd.run()
            },
        )))
    }
}

/// Trace packets on the Linux kernel
///
/// retis is a tool for capturing networking-related events from the system using ebpf and analyzing them.
#[derive(Args, Debug, Default)]
pub(crate) struct MainConfig {
    #[arg(
        long,
        value_parser=PossibleValuesParser::new(["error", "warn", "info", "debug", "trace"]),
        default_value = "info",
        help = "Log level",
    )]
    pub(crate) log_level: String,
    #[arg(
        long,
        short,
        value_delimiter = ',',
        help = "Comma separated list of profile names to apply"
    )]
    pub(crate) profile: Vec<String>,
    #[arg(
        long,
        help = "Path to kernel configuration (e.g. /boot/config-6.3.8-200.fc38.x86_64; default: auto-detect)"
    )]
    pub(crate) kconf: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub(crate) struct RetisCli {
    subcommands: Vec<Box<dyn SubCommand>>,
}

impl RetisCli {
    /// Allocate and return a new RetisCli object that will parse the command arguments.
    pub(crate) fn new() -> Result<Self> {
        let mut cli = RetisCli::default();
        cli.add_subcommand(Box::new(Collect::new()?))?;
        cli.add_subcommand(Box::new(Print::new()?))?;
        cli.add_subcommand(Box::new(Sort::new()?))?;
        #[cfg(feature = "python")]
        cli.add_subcommand(Box::new(PythonCli::new()?))?;
        cli.add_subcommand(Box::new(Pcap::new()?))?;
        cli.add_subcommand(Box::new(Inspect::new()?))?;
        cli.add_subcommand(Box::new(ProfileCmd::new()?))?;
        cli.add_subcommand(Box::new(Complete::new()?))?;

        #[cfg(feature = "benchmark")]
        cli.add_subcommand(Box::new(Benchmark::new()?))?;

        Ok(cli)
    }

    fn add_subcommand(&mut self, sub: Box<dyn SubCommand>) -> Result<&mut Self> {
        let name = sub.name();

        if self.subcommands.iter().any(|s| s.name() == name) {
            bail!("Subcommand already registered")
        }

        self.subcommands.push(sub);
        Ok(self)
    }

    /// Build a CliConfig by parsing the arguments
    pub(crate) fn parse(self) -> CliConfig {
        self.parse_from(env::args_os()).unwrap_or_else(|e| e.exit())
    }

    /// Enhance arguments with provided profile.
    fn enhance_profile(
        main_config: &MainConfig,
        subcommand: &str,
        args: &mut Vec<OsString>,
    ) -> Result<()> {
        if main_config.profile.is_empty() {
            return Ok(());
        }

        for name in main_config.profile.iter() {
            let profile = Profile::find(name.as_str())?;
            let mut extra_args = profile.cli_args(subcommand)?;
            args.append(&mut extra_args);
        }
        Ok(())
    }

    /// Build a CliConfig by parsing the given list of arguments.
    /// This function should be only used directly by unit tests.
    pub(crate) fn parse_from<I, T>(mut self, args: I) -> Result<CliConfig, ClapError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let pkg_version = option_env!("RELEASE_VERSION").unwrap_or("unspec");
        let pkg_name = option_env!("RELEASE_NAME").unwrap_or("unreleased");

        let version = if cfg!(debug_assertions) {
            format!("{} [dbg] (\"{}\")", pkg_version, pkg_name)
        } else {
            format!("{} (\"{}\")", pkg_version, pkg_name)
        };

        let mut args: Vec<OsString> = args.into_iter().map(|x| x.into()).collect();
        let mut command = MainConfig::augment_args(Command::new("retis"))
            .version(version)
            .disable_help_subcommand(true)
            .infer_subcommands(true)
            .subcommand_required(true);

        // Add full subcommands so that the main help shows them.
        for sub in self.subcommands.iter_mut() {
            command = command.subcommand(sub.command().expect("command failed"));
        }

        // Run once (before profile expansion) to set the logging level.
        let matches = command.clone().try_get_matches_from(args.iter())?;

        let mut main_config = MainConfig::default();
        main_config.update_from_arg_matches(&matches)?;

        let log_level = main_config.log_level.as_str();
        let log_level = LevelFilter::from_str(log_level).map_err(|e| {
            command.error(
                ErrorKind::InvalidValue,
                format!("Invalid log_level: {log_level} ({e})"),
            )
        })?;
        let logger = Logger::init(log_level).expect("failed to initialize logger");
        set_libbpf_rs_print_callback(log_level);

        let mut subcommand = matches
            .subcommand_name()
            .and_then(|name| self.subcommands.drain(..).find(|s| s.name() == name))
            .ok_or_else(||
                // There is no subcommand or it's invalid. Re-run the match to generate
                // the right clap error that to be printed nicely.
                command
                    .try_get_matches_from_mut(args.iter())
                    .expect_err("clap should fail with no arguments"))?;

        RetisCli::enhance_profile(&main_config, subcommand.name().as_str(), &mut args)
            .map_err(|err| command.error(ErrorKind::InvalidValue, format!("{err}")))?;

        debug!(
            "Resulting CLI arguments: {}",
            args.iter()
                .map(|o| o.as_os_str().to_str().unwrap_or("<encoding error>"))
                .collect::<Vec<&str>>()
                .join(" ")
        );

        // Final round of parsing
        let matches = match cfg!(test) {
            true => command.try_get_matches_from_mut(args.iter())?,
            false => command
                .try_get_matches_from_mut(args.iter())
                .unwrap_or_else(|e| e.exit()),
        };
        let (_, matches) = matches
            .subcommand()
            .expect("full parsing did not find subcommand");

        // Update subcommand options.
        match cfg!(test) {
            true => subcommand.update_from_arg_matches(matches)?,
            false => subcommand
                .update_from_arg_matches(matches)
                .unwrap_or_else(|e| e.exit()),
        }

        Ok(CliConfig {
            command,
            main_config,
            subcommand,
            logger,
        })
    }
}


/// CliConfig represents the result of the Full CLI parsing
#[derive(Debug)]
pub(crate) struct CliConfig {
    pub(crate) command: Command,
    pub(crate) main_config: MainConfig,
    pub(crate) subcommand: Box<dyn SubCommand>,
    pub(crate) logger: Arc<Logger>,
}

/// Type of the "format" argument.
// It is an enum that maps 1:1 with the formats defined in events library.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub(crate) enum CliDisplayFormat {
    SingleLine,
    #[default]
    MultiLine,
}
