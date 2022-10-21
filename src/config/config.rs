#![allow(dead_code)] // FIXME

use anyhow::{bail, Result};
use std::{collections::HashSet, env, ffi::OsString};

use clap::{ArgMatches, Args, Command, FromArgMatches};

pub(crate) struct Cli {
    command: Command,
    collectors: HashSet<String>,
    matches: Option<ArgMatches>,
}

impl Cli {
    /// Allocate and return a new Cli object adding the main arguments.
    pub(crate) fn new() -> Result<Self> {
        let command = Command::new("packet-tracer");
        Ok(Cli {
            command,
            collectors: HashSet::new(),
            matches: None,
        })
    }

    /// Register a new collector with a specific name augmenting the Cli's
    /// arguments with those of the templated Args struct.
    pub(crate) fn register_collector<T>(&mut self, name: &'static str) -> Result<()>
    where
        T: Args,
    {
        if name == "main" {
            bail!("'main' is a reserved section name");
        }

        let name = String::from(name);
        if self.collectors.get(&name).is_some() {
            bail!("config with name {} already registered", name);
        }
        self.collectors.insert(name.to_owned());

        self.command = self.command.to_owned().next_help_heading(
            format!("Collector: {}", name));

        self.command = T::augment_args_for_update(self.command.to_owned());

        Ok(())
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
        // augment_args places the struct's documentation comments (///) at the program's help
        // string replacing whatever was there originally. In order to keep a reasonable help
        // string while allowing modules to write documentation comments on their configuration
        // section structs, use the MainConfig to augment the args last.
        if self.collectors.get("main").is_none() {
            self.command = MainConfig::augment_args(self.command.to_owned());
            self.collectors.insert("main".to_string());
        }

        let matches = match try_get {
            true => self.command.to_owned().try_get_matches_from(iter)?,
            false => self.command.to_owned().get_matches_from(iter),
        };

        self.matches = Some(matches);
        Ok(())
    }

    /// On an alrady parsed Cli object, retrieve a specific configuration Section by name (and type).
    pub(crate) fn get_section<T>(&self, name: &str) -> Result<T>
    where
        T: Default + FromArgMatches,
    {
        self.collectors.get(name).expect("section not registered");
        let matches = self.matches.as_ref().expect("cli not parsed");
        let mut target = T::default();
        target.update_from_arg_matches(matches)?;
        Ok(target)
    }
}

/// Trace packets on the Linux kernel
///
/// Insert a whole lot of ebpf programs into the Linux kernel (and OvS) to find packets wherever
/// thy are.
#[derive(Args, Default)]
pub(crate) struct MainConfig {}

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
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col2>("col2").is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col1>("col1").is_err());
        Ok(())
    }

    #[test]
    fn cli_parse() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col2>("col2").is_ok());
        assert!(cli.parse_from(["--help"], true).is_ok());
        Ok(())
    }

    #[test]
    fn cli_parse_args() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(
                vec![
                    "packet-tracer",
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
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--no-exixts", "foo"], true)
            .is_err());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--col2-flag", "true"], true)
            .is_err());
        Ok(())
    }

    #[test]
    fn cli_parse_args_enum() -> Result<()> {
        let mut cli = Cli::new()?;
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--col1-choice", "baz"], true)
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
        assert!(cli.register_collector::<Col1>("col1").is_ok());
        assert!(cli.register_collector::<Col2>("col2").is_ok());
        assert!(cli
            .parse_from(vec!["packet-tracer", "--col1-choice", "wrong"], true)
            .is_err());
        Ok(())
    }
}
