#![allow(dead_code)] // FIXME

use anyhow::{bail, Result};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
};

use clap::{
    error::{Error, ErrorKind},
    ArgMatches, Args, Command, FromArgMatches,
};

pub(crate) struct Cli {
    command: Command,
    sub_cli: SubCli,
    matches: Option<ArgMatches>,
}

impl Cli {
    /// Allocate and return a new Cli object adding the main arguments.
    pub(crate) fn new() -> Result<Self> {
        let command = MainConfig::augment_args(Command::new("packet-tracer"));
        Ok(Cli {
            command,
            sub_cli: SubCli::new()?,
            matches: None,
        })
    }

    /// Register a new collector with a specific name and no arguments.
    pub(crate) fn register_collector(&mut self, name: &'static str) -> Result<()>
    {
        if name == "main" {
            bail!("'main' is a reserved section name");
        }
        self.sub_cli.register_collector(name)

    }

    /// Register a new collector with a specific name augmenting the Cli's
    /// arguments with those of the templated Args struct.
    pub(crate) fn register_collector_args<T>(&mut self, name: &'static str) -> Result<()>
    where
        T: Args,
    {
        if name == "main" {
            bail!("'main' is a reserved section name");
        }
        self.sub_cli.register_collector_args::<T>(name)
    }

    /// Parse binary arguments.
    pub(crate) fn parse(&mut self) -> Result<()> {
        self.parse_from(&mut env::args_os(), false)
    }

    /// Parse an interator of strings as input arguments. Useful for testing.
    fn parse_from<I, T>(&mut self, iter: I, try_get: bool) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        self.command = self.sub_cli.augment(self.command.to_owned())?;

        let matches = match try_get {
            true => self.command.to_owned().try_get_matches_from(iter)?,
            false => self.command.to_owned().get_matches_from(iter),
        };

        match try_get {
            true => {
                self.sub_cli
                    .update_from_arg_matches(&matches, &self.command)?;
            }
            false => {
                self.sub_cli
                    .update_from_arg_matches(&matches, &self.command)
                    .unwrap_or_else(|e| e.exit());
            }
        }

        self.matches = Some(matches);
        Ok(())
    }

    /// Return the main arguments of a parsed Cli.
    pub(crate) fn get_main_args(&mut self) -> Result<MainConfig> {
        let matches = self.matches.as_ref().expect("cli not parsed");
        MainConfig::from_arg_matches(matches).map_err(|e| anyhow::anyhow!(e))
    }

    /// Return the SubCommands enum of a parsed Cli.
    pub(crate) fn get_subcommand(&self) -> Option<&SubCommand> {
        self.sub_cli.args.as_ref()
    }

    /// On an alrady parsed Cli object, retrieve a specific configuration Section by name (and type).
    pub(crate) fn get_section<T>(&self, name: &str) -> Result<T>
    where
        T: Default + FromArgMatches,
    {
        let matches = self.matches.as_ref().expect("cli not parsed");
        self.sub_cli.get_section::<T>(name, matches)
    }
}

/// Trace packets on the Linux kernel
///
/// packet-tracer is of capturing networking-related events from the system using ebpf and analyze them.
#[derive(Args, Default)]
pub(crate) struct MainConfig {}

/// Variant containing all the subcommands and their global configuration.
#[derive(Debug)]
pub(crate) enum SubCommand {
    Collect(CollectArgs),
}

/// Global configuration of the "collect" subcommand.
#[derive(Args, Debug)]
pub(crate) struct CollectArgs {
    #[arg(long)]
    ebpf_debug: Option<String>,
}

/// SubCli handles the subcommand argument parsing.
// We need to keep a clap::Command for each subcommand so we can dynamically augment them. This is
// the main reason why we not use add a #[derive(Parser)] to define the subcommands.
//
// Instead, the taken approach is to create all the subcommands and, after augmentation, manually
// add them (augment_subcommand) to the main Command. The drawback of this approach is we don'the
// have the convenient Variat that stores the executes subcommand and its arguments, so we create
// that manually as well during.
// SubCli must be used in a particular order:
//
// let s = SubCli::new();
// s.register_collector_args::<SomeCollector>("some");
// s.register_collector("other");
// [...]
// let cmd = s.augment(Command::new("myapp"));
// s.update_from_arg_matches(cmd.get_matches_from(vec!["myapp", "collect", "--someopt"]));
// let some: SomeCollector = s.get_section("some");
#[derive(Debug)]
pub(crate) struct SubCli {
    args: Option<SubCommand>,
    commands: HashMap<String, Command>,
    collectors: HashSet<String>,
    matches: Option<ArgMatches>,
}

impl SubCli {
    /// Create a new SubCli.
    pub(crate) fn new() -> Result<Self> {
        let mut commands = HashMap::new();
        commands.insert(
            "collect".to_string(),
            CollectArgs::augment_args(Command::new("collect")),
        );

        Ok(SubCli {
            args: None,
            collectors: HashSet::new(),
            matches: None,
            commands,
        })
    }

    /// Sets the "about" and "long_about" strings of the internal subcommands.
    fn set_subcommand_help(&mut self) {
        let long_about = format!(
            "Collectors are modules that extract \
            events from different places of the kernel or userspace daemons \
            using ebpf.\n\n\
            The following collectors are supported: [{}]\n",
            self.collectors
                .iter()
                .cloned()
                .collect::<Vec<String>>()
                .join(", ")
        );

        let collect = self
            .commands
            .remove("collect")
            .unwrap()
            .about("Collect events")
            .long_about(long_about);
        self.commands.insert("collect".to_string(), collect);
    }

    /// Augment the command with the SubCli arguments defined.
    fn augment(&mut self, command: Command) -> Result<Command> {
        // After all dynamig augmentation is done, we need to overwrite the help (about and
        // about_long) strings. Otherwise the ones from the document comments (the ones with
        // "///" of the last dynamic section will be used.
        self.set_subcommand_help();

        let mut cmd = command.arg_required_else_help(true);
        for subcommand in self.commands.values() {
            cmd = cmd.to_owned().subcommand(subcommand.clone());
        }
        Ok(cmd)
    }

    /// Register a new collector with a specific name and no arguments.
    pub(crate) fn register_collector(&mut self, name: &'static str) -> Result<()>
    {
        let name = String::from(name);
        if self.collectors.get(&name).is_some() {
            bail!("config with name {} already registered", name);
        }
        self.collectors.insert(name.to_owned());
        Ok(())
    }
    /// Register a new collector with a specific name augmenting the "collect"
    /// arguments with those of the templated Args struct.
    pub(crate) fn register_collector_args<T>(&mut self, name: &'static str) -> Result<()>
    where
        T: Args,
    {
        self.register_collector(name)?;

        let command = self
            .commands
            .remove("collect")
            .unwrap()
            .next_help_heading(format!("{} collector", name));

        self.commands
            .insert("collect".to_string(), T::augment_args_for_update(command));

        Ok(())
    }

    /// Retrieve a specific configuration section by name (and type).
    /// It must be called after update_from_arg_matches().
    /// T is initialized using it's Default trait before being updated with the content
    /// of the cli matches.
    pub(crate) fn get_section<T>(&self, name: &str, _: &ArgMatches) -> Result<T>
    where
        T: Default + FromArgMatches,
    {
        self.collectors.get(name).expect("section not registered");
        let mut target = T::default();
        target.update_from_arg_matches(
            self.matches
                .as_ref()
                .expect("called get_section before update_from_arg_matches"),
        )?;
        Ok(target)
    }

    /// Updates itself based on the cli matches.
    pub(crate) fn update_from_arg_matches(
        &mut self,
        matches: &ArgMatches,
        command: &Command,
    ) -> Result<(), clap::error::Error> {
        match matches.subcommand() {
            Some(("collect", args)) => {
                println!("{:?}", args);
                self.args = Some(SubCommand::Collect(CollectArgs::from_arg_matches(args)?));
                self.matches = Some(args.clone());
            }
            Some((_, _)) => {
                return Err(Error::raw(
                    ErrorKind::InvalidSubcommand,
                    "Valid subcommands are `collect`",
                )
                .with_cmd(command))
            }
            None => {
                return Err(
                    Error::raw(ErrorKind::MissingSubcommand, "Missing subcommand")
                        .with_cmd(command),
                )
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::ValueEnum;

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
    enum Col1Opts {
        Foo,
        Bar,
        Baz,
    }

    #[derive(Clone, Args)]
    struct Col1 {
        /// Module 1 someopt
        #[arg(id = "col1-someopt", long)]
        someopt: Option<String>,

        /// Module 1 some other opts
        #[arg(id = "col1-choice", long)]
        choice: Option<Col1Opts>,

        /// Module 1 has a flag true by default
        #[arg(id = "col1-flag", long)]
        flag: Option<bool>,
    }

    impl Default for Col1 {
        fn default() -> Self {
            Col1 {
                someopt: None,
                choice: Some(Col1Opts::Foo),
                flag: Some(true),
            }
        }
    }

    #[derive(Clone, Default, Args)]
    struct Col2 {
        /// Col2 also has someopt
        #[arg(id = "col2-someopt", long)]
        someopt: Option<String>,
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        Ok(())
    }

    #[test]
    fn register_collectors_noargs() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector("col1").is_ok());
        assert!(cli.register_collector("col1").is_err());
        Ok(())
    }


    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col1>("col1").is_err());
        Ok(())
    }

    #[test]
    fn cli_parse() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        let err = cli.parse_from(vec!["packet-tracer", "collect", "--help"], true);
        assert!(
            err.is_err()
                && err
                    .unwrap_err()
                    .downcast::<clap::error::Error>()
                    .expect("is clap error")
                    .kind()
                    == ErrorKind::DisplayHelp
        );
        Ok(())
    }

    #[test]
    fn cli_parse_args() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(
                vec![
                    "packet-tracer",
                    "collect",
                    "--col1-someopt",
                    "foo",
                    "--col2-someopt",
                    "bar"
                ],
                true
            )
            .is_ok());

        let col1 = cli.get_section::<Col1>("col1");
        let col2 = cli.get_section::<Col2>("col2");
        assert!(col1.is_ok());
        assert!(col2.is_ok());

        let col1 = col1.unwrap();
        let col2 = col2.unwrap();

        assert!(col1.someopt == Some("foo".to_string()));
        assert!(col2.someopt == Some("bar".to_string()));
        // Default values:
        assert!(col1.flag == Some(true));
        assert!(col1.choice == Some(Col1Opts::Foo));

        Ok(())
    }

    #[test]
    fn cli_parse_args_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "collect", "--no-exixts", "foo"], true)
            .is_err());

        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(
                vec!["packet-tracer", "collect", "--col2-flag", "true"],
                true
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_parse_args_enum() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli
            .parse_from(
                vec!["packet-tracer", "collect", "--col1-choice", "baz"],
                true
            )
            .is_ok());
        let col1 = cli.get_section::<Col1>("col1");
        assert!(col1.is_ok());
        let col1 = col1.unwrap();

        assert!(col1.choice == Some(Col1Opts::Baz));

        Ok(())
    }

    #[test]
    fn cli_parse_args_enum_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(
                vec!["packet-tracer", "collect", "--col1-choice", "wrong"],
                true
            )
            .is_err());
        Ok(())
    }
}
