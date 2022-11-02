#![allow(dead_code)] // FIXME

use anyhow::{bail, Result};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
};

use clap::{
    builder::PossibleValuesParser,
    error::{Error, ErrorKind},
    Arg, ArgMatches, Args, Command, FromArgMatches,
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
    pub(crate) fn register_collector(&mut self, name: &'static str) -> Result<()> {
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
    /// Parsing failure exit the program.
    pub(crate) fn parse(&mut self) -> Result<()> {
        self.do_parse_from(&mut env::args_os(), false)
    }

    /// Parse an interator of strings as input arguments. Useful for testing.
    /// Parsing failures are returned.
    pub(crate) fn parse_from<I, T>(&mut self, iter: I) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        self.do_parse_from(iter, true)
    }

    // Parse an interator of strings as input arguments
    // "try" determines if the errors should be returned or if the program should
    // exit.
    fn do_parse_from<I, T>(&mut self, iter: I, r#try: bool) -> Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        self.command = self.sub_cli.augment(self.command.to_owned())?;

        let matches = match r#try {
            true => self.command.to_owned().try_get_matches_from(iter)?,
            false => self.command.to_owned().get_matches_from(iter),
        };

        match r#try {
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
    #[arg(long, default_value = "false")]
    pub(crate) ebpf_debug: bool,

    // Some of the options that we want for this arg are not available in clap's derive interface
    // so both the argument definition and the field population will be done manually.
    #[arg(skip)]
    pub(crate) collectors: Vec<String>,
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
        let collect = CollectArgs::augment_args(Command::new("collect")).arg(
            Arg::new("collectors")
                .long("collectors")
                .short('c')
                .value_delimiter(',')
                .help("comma-separated list of collectors to enable"),
        );
        commands.insert("collect".to_string(), collect);

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

    /// Update "--collectors" argument in "collect" subcommand so its possible values and default
    /// value match the names of the dynamically added collectors.
    fn update_collector_arg(&mut self) -> Result<()> {
        let possible_collectors = Vec::from_iter(self.collectors.iter().map(|x| x.to_owned()));
        let collect = self
            .commands
            .remove("collect")
            .unwrap()
            .mut_arg("collectors", |a| {
                a.value_parser(PossibleValuesParser::new(possible_collectors.clone()))
                    .default_value(possible_collectors.join(","))
            });
        self.commands.insert("collect".to_string(), collect);
        Ok(())
    }

    /// Augment the command with the SubCli arguments defined.
    fn augment(&mut self, command: Command) -> Result<Command> {
        // After all dynamig augmentation is done, we need to overwrite the help (about and
        // about_long) strings. Otherwise the ones from the document comments (the ones with
        // "///" of the last dynamic section will be used.
        self.set_subcommand_help();
        self.update_collector_arg()?;

        let mut cmd = command.arg_required_else_help(true);
        for subcommand in self.commands.values() {
            cmd = cmd.to_owned().subcommand(subcommand.clone());
        }
        Ok(cmd)
    }

    /// Register a new collector with a specific name and no arguments.
    pub(crate) fn register_collector(&mut self, name: &'static str) -> Result<()> {
        let name = String::from(name);
        if self.collectors.get(&name).is_some() {
            bail!("config with name {} already registered", name);
        }
        self.collectors.insert(name);
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
                let matches = args.clone();
                let mut collect = CollectArgs::from_arg_matches(args)?;
                // Manually set collectors from args.
                collect.collectors = matches
                    .get_many("collectors")
                    .expect("collectors are mandatory")
                    .map(|x: &String| x.to_owned())
                    .collect();

                self.matches = Some(matches);
                self.args = Some(SubCommand::Collect(collect));
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
        let err = cli.parse_from(vec!["packet-tracer", "collect", "--help"]);
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
            .parse_from(vec![
                "packet-tracer",
                "collect",
                "--col1-someopt",
                "foo",
                "--col2-someopt",
                "bar"
            ])
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
            .parse_from(vec!["packet-tracer", "collect", "--no-exixts", "foo"])
            .is_err());

        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "collect", "--col2-flag", "true"])
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_parse_args_enum() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "collect", "--col1-choice", "baz"])
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
            .parse_from(vec!["packet-tracer", "collect", "--col1-choice", "wrong"])
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_select_collectors() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "collect", "--collectors", "col1"])
            .is_ok());
        let command = cli.get_subcommand();
        assert!(command.is_some());
        assert!(matches!(
                command.as_ref().unwrap(),
                SubCommand::Collect(x) if x.collectors == ["col1"]));
        Ok(())
    }

    #[test]
    fn cli_select_all_collectors() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec![
                "packet-tracer",
                "collect",
                "--collectors",
                "col1,col2"
            ])
            .is_ok());
        let command = cli.get_subcommand();
        assert!(command.is_some());
        assert!(matches!(
                command.as_ref().unwrap(),
                SubCommand::Collect(x) if x.collectors == ["col1", "col2"]));
        Ok(())
    }

    #[test]
    fn cli_collectors_default() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli.parse_from(vec!["packet-tracer", "collect"]).is_ok());
        let command = cli.get_subcommand();
        assert!(command.is_some());
        assert!(matches!(
                command.as_ref().unwrap(),
                    SubCommand::Collect(x) if x.collectors == ["col1", "col2"]));
        Ok(())
    }

    #[test]
    fn cli_collectors_err() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector_args::<Col1>("col1").is_ok());
        assert!(cli.register_collector_args::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec![
                "packet-tracer",
                "collect",
                "--collectors",
                "col1,noexists"
            ])
            .is_err());
        Ok(())
    }
}
