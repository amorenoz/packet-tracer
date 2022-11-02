//! # Collectors
//!
//! Collectors are modules gathering information, mainly collecting events
//! and/or appropriate data; they are at the core of the tool.
//!
//! Depending on the system capabilities, version, etc. collectors might fail at
//! setting up probes or interfacing with their target. Collectors should try
//! hard to work on various environments though; a few pointers to achieve this:
//! - The mandatory part should be kept minimal.
//! - If a probe point or a feature isn't available and if applicable, it should
//!   try to fallback to other approaches. The result might be a loss of
//!   information, which is better than failing. A warning can be displayed in
//!   such cases.
//!   e.g. attaching to kfree_skb_reason in the Linux kernel is better than
//!   attaching to kfree_skb, as the drop reason is otherwise lost, but it is
//!   acceptable as a fallback (mainly for older kernels).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use log::{error, warn};

use crate::config::{Cli, SubCommand};
use crate::core::probe;

mod skb;
use skb::SkbCollector;

mod ovs;
use ovs::OvsCollector;

/// Generic trait representing a collector. All collectors are required to
/// implement this, as they'll be manipulated through this trait.
trait Collector {
    /// Allocate and return a new instance of the collector, using only default
    /// values for its internal fields.
    fn new() -> Result<Self>
    where
        Self: Sized;
    /// Register command line arguments on the provided Cli object.
    fn register_cli(&self, cli: &mut Cli) -> Result<()>;
    /// Return the name of the collector. It *has* to be unique among all the
    /// collectors.
    fn name(&self) -> &'static str;
    /// Initialize the collector, likely to be used to pass configuration data
    /// such as filters or command line arguments. We need to split the new &
    /// the init phase for collectors, to allow giving information to the core
    /// as part of the collector registration and only then feed the collector
    /// with data coming from the core. Checks for the mandatory part of the
    /// collector should be done here.
    fn init(&mut self, kernel: &mut probe::Kernel, cli: &Cli) -> Result<()>;
    /// Start the group of events (non-probes).
    fn start(&mut self) -> Result<()>;
}

/// Group of collectors. Used to handle a set of collectors and to perform
/// group actions.
pub(crate) struct Group {
    list: HashMap<String, Box<dyn Collector>>,
    kernel: probe::Kernel,
}

impl Group {
    fn new() -> Result<Group> {
        Ok(Group {
            list: HashMap::new(),
            kernel: probe::Kernel::new()?,
        })
    }

    /// Register a collector to the group.
    ///
    /// ```
    /// group
    ///     .register(Box::new(FirstCollector::new()?))?
    ///     .register(Box::new(SecondCollector::new()?))?
    ///     .register(Box::new(ThirdCollector::new()?))?;
    /// ```
    fn register(&mut self, collector: Box<dyn Collector>) -> Result<&mut Self> {
        let name = String::from(collector.name());

        // Ensure uniqueness of the collector name. This is important as their
        // name is used as a key.
        if self.list.get(&name).is_some() {
            bail!(
                "Could not insert collector '{}'; name already registered",
                name
            );
        }

        self.list.insert(name, collector);
        Ok(self)
    }

    /// Register all collectors' command line arguments by calling their register_cli function.
    pub(crate) fn register_cli(&self, cli: &mut Cli) -> Result<()> {
        for (_, c) in self.list.iter() {
            // Cli registration errors are fatal.
            c.register_cli(cli)?;
        }
        Ok(())
    }

    /// Initialize all collectors by calling their `init()` function. Collectors
    /// failing to initialize will be removed from the group.
    pub(crate) fn init(&mut self, cli: &Cli) -> Result<()> {
        let mut to_remove = Vec::new();
        let args = match cli
            .get_subcommand()
            .ok_or_else(|| anyhow!("subcommand unavailable"))?
        {
            SubCommand::Collect(args) => args,
        };

        // Try initializing all collectors in the group. Failing ones are
        // put on a list for future removal.
        for name in &args.collectors {
            let c = self.list.get_mut(name).ok_or_else(|| {
                anyhow!("cli enabled a collector ({}) that was not registered", name)
            })?;
            if let Err(e) = c.init(&mut self.kernel, cli) {
                to_remove.push(c.name());
                error!(
                    "Could not initialize collector '{}', unregistering: {}",
                    c.name(),
                    e
                );
            }
        }

        // Remove all collectors that failed their initialization at the
        // previous step.
        for name in to_remove.iter() {
            self.list.remove(*name);
        }

        Ok(())
    }

    /// Start the event retrieval for all collectors in the group by calling
    /// their `start()` function. Collectors failing to start the event
    /// retrieval will be kept in the group.
    pub(crate) fn start(&mut self, _: &Cli) -> Result<()> {
        self.kernel.attach()?;

        for (_, c) in self.list.iter_mut() {
            if c.start().is_err() {
                warn!("Could not start '{}'", c.name());
            }
        }
        Ok(())
    }
}

/// Allocate collectors and retrieve a group containing them, used to perform
/// batched operations. This is the primary entry point for manipulating the
/// collectors.
pub(crate) fn get_collectors() -> Result<Group> {
    let mut group = Group::new()?;

    // Register all collectors here.
    group.register(Box::new(SkbCollector::new()?))?;
    group.register(Box::new(OvsCollector::new()?))?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{arg, Args};

    struct DummyCollectorA;
    struct DummyCollectorB;

    #[derive(Args, Default)]
    struct DummyCollectorAArgs {
        #[arg(long)]
        foo: Option<String>,
    }

    impl Collector for DummyCollectorA {
        fn new() -> Result<DummyCollectorA> {
            Ok(DummyCollectorA)
        }
        fn name(&self) -> &'static str {
            "dummy-a"
        }
        fn register_cli(&self, cli: &mut Cli) -> Result<()> {
            cli.register_collector_args::<DummyCollectorAArgs>("dummy-a")
        }
        fn init(&mut self, _: &mut probe::Kernel, _: &Cli) -> Result<()> {
            Ok(())
        }
        fn start(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Collector for DummyCollectorB {
        fn new() -> Result<DummyCollectorB> {
            Ok(DummyCollectorB)
        }
        fn name(&self) -> &'static str {
            "dummy-b"
        }
        fn register_cli(&self, cli: &mut Cli) -> Result<()> {
            cli.register_collector("dummy-b")
        }
        fn init(&mut self, _: &mut probe::Kernel, _: &Cli) -> Result<()> {
            bail!("Could not initialize");
        }
        fn start(&mut self) -> Result<()> {
            bail!("Could not start");
        }
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut group = Group::new()?;
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_ok());
        assert!(group.register(Box::new(DummyCollectorB::new()?)).is_ok());
        Ok(())
    }

    #[test]
    fn register_cli() -> Result<()> {
        let mut group = Group::new()?;
        let mut cli = Cli::new()?;
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_ok());
        assert!(group.register(Box::new(DummyCollectorB::new()?)).is_ok());

        assert!(group.register_cli(&mut cli).is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut group = Group::new()?;
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_ok());
        assert!(group.register(Box::new(DummyCollectorA::new()?)).is_err());
        Ok(())
    }

    #[test]
    fn get_collectors() -> Result<()> {
        assert!(super::get_collectors().is_ok());
        Ok(())
    }

    #[test]
    fn init_collectors() -> Result<()> {
        let mut group = Group::new()?;
        let mut cli = Cli::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        let mut kernel = probe::Kernel::new()?;

        assert!(dummy_a.init(&mut kernel, &cli).is_ok());
        assert!(dummy_b.init(&mut kernel, &cli).is_err());

        group.register_cli(&mut cli)?;
        cli.parse_from(vec!["prog", "collect"])?;
        assert!(group.init(&cli).is_ok());
        Ok(())
    }

    #[test]
    fn init_collectors_disabled() -> Result<()> {
        let mut group = Group::new()?;
        let mut cli = Cli::new()?;

        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        group.register_cli(&mut cli)?;
        cli.parse_from(vec!["prog", "collect", "--collectors", "dummy-a"])?;
        assert!(group.init(&cli).is_ok());
        Ok(())
    }

    #[test]
    fn start_collectors() -> Result<()> {
        let mut group = Group::new()?;
        let cli = Cli::new()?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(Box::new(DummyCollectorA::new()?))?;
        group.register(Box::new(DummyCollectorB::new()?))?;

        assert!(dummy_a.start().is_ok());
        assert!(dummy_b.start().is_err());
        assert!(group.start(&cli).is_ok());
        Ok(())
    }
}
