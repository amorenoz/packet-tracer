use std::{
    collections::{HashMap, HashSet},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::{error, info, warn};
use signal_hook::{consts::SIGINT, iterator::Signals};

use super::{
    cli::Collect,
    output::{get_processors, JsonFormat},
};
#[cfg(not(test))]
use crate::core::probe::kernel::config::init_stack_map;
use crate::{
    cli::{dynamic::DynamicCommand, CliConfig},
    core::{
        events::{
            bpf::{BpfEventsFactory, CommonEvent},
            EventFactory, EventSectionFactory,
        },
        kernel::Symbol,
        probe::{self, kernel::KernelEvent, Probe},
    },
    module::{
        ovs::{OvsCollector, OvsEvent},
        skb::{SkbCollector, SkbEvent},
        skb_tracking::{SkbTrackingCollector, SkbTrackingEvent},
        ModuleId,
    },
};

/// Generic trait representing a collector. All collectors are required to
/// implement this, as they'll be manipulated through this trait.
pub(crate) trait Collector {
    /// Allocate and return a new instance of the collector, using only default
    /// values for its internal fields.
    fn new() -> Result<Self>
    where
        Self: Sized;
    /// List of kernel data types the collector can retrieve data from, if any.
    /// This is useful for registering dynamic collectors, and is used later for
    /// checking requested probes are not a no-op.
    fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
        None
    }
    ///Register command line arguments on the provided DynamicCommand object
    fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()>;
    /// Initialize the collector, likely to be used to pass configuration data
    /// such as filters or command line arguments. We need to split the new &
    /// the init phase for collectors, to allow giving information to the core
    /// as part of the collector registration and only then feed the collector
    /// with data coming from the core. Checks for the mandatory part of the
    /// collector should be done here.
    ///
    /// This function should only return an Error in case it's fatal as this
    /// will make the whole program to fail. In general collectors should try
    /// hard to run in various setups, see the `crate::collector` top
    /// documentation for more information.
    fn init(&mut self, cli: &CliConfig, probes: &mut probe::ProbeManager) -> Result<()>;
    /// Start the group of events (non-probes).
    fn start(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Group of collectors. Used to handle a set of collectors and to perform
/// group actions.
pub(crate) struct Group {
    list: HashMap<ModuleId, Box<dyn Collector>>,
    factory: Box<dyn EventFactory>,
    section_factories: Option<HashMap<ModuleId, Box<dyn EventSectionFactory>>>,
    probes: probe::ProbeManager,
    known_kernel_types: HashSet<String>,
}

impl Group {
    fn new(factory: Box<dyn EventFactory>) -> Result<Group> {
        let mut section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>> = HashMap::new();
        #[cfg(not(test))]
        let mut probes = probe::ProbeManager::new()?;
        #[cfg(test)]
        let probes = probe::ProbeManager::new()?;

        #[cfg(not(test))]
        let sm = init_stack_map()?;
        #[cfg(not(test))]
        probes.reuse_map("stack_map", sm.fd())?;

        let kernel_event = KernelEvent {
            #[cfg(not(test))]
            stack_map: Some(sm),
            ..Default::default()
        };

        section_factories.insert(ModuleId::Common, Box::<CommonEvent>::default());
        section_factories.insert(ModuleId::Kernel, Box::new(kernel_event));

        Ok(Group {
            list: HashMap::new(),
            factory,
            section_factories: Some(section_factories),
            probes,
            known_kernel_types: HashSet::new(),
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
    fn register(
        &mut self,
        id: ModuleId,
        collector: Box<dyn Collector>,
        section_factory: Box<dyn EventSectionFactory>,
    ) -> Result<&mut Self> {
        // Ensure uniqueness of the collector name. This is important as their
        // name is used as a key.
        if self.list.get(&id).is_some() {
            bail!(
                "Could not insert collector '{}'; name already registered",
                id,
            );
        }

        match &mut self.section_factories {
            Some(factories) => factories.insert(id, section_factory),
            None => bail!("Section factories map no found"),
        };

        self.list.insert(id, collector);
        Ok(self)
    }

    /// Initialize all collectors by calling their `init()` function.
    pub(crate) fn init(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        probe::common::set_ebpf_debug(collect.args()?.ebpf_debug)?;
        if collect.args()?.stack {
            self.probes.add_probe_opt(probe::ProbeOption::StackTrace);
        }

        // Try initializing all collectors in the group.
        for name in &collect.args()?.collectors {
            let id = ModuleId::from_str(name)?;
            let c = self
                .list
                .get_mut(&id)
                .ok_or_else(|| anyhow!("unknown collector {}", name))?;

            if let Err(e) = c.init(cli, &mut self.probes) {
                bail!("Could not initialize the {} collector: {}", id, e);
            }

            // If the collector provides known kernel types, meaning we have a
            // dynamic collector, retrieve and store them for later processing.
            if let Some(kt) = c.known_kernel_types() {
                kt.into_iter().for_each(|x| {
                    self.known_kernel_types.insert(x.to_string());
                });
            }
        }

        // Setup user defined probes.
        for probe in collect.args()?.probes.iter() {
            self.probes.add_probe(self.parse_probe(probe)?)?;
        }
        Ok(())
    }

    /// Register all collectors' command line arguments by calling their register_cli function.
    pub(crate) fn register_cli(&self, cmd: &mut DynamicCommand) -> Result<()> {
        for (_, c) in self.list.iter() {
            // Cli registration errors are fatal.
            c.register_cli(cmd)?;
        }
        Ok(())
    }

    /// Start the event retrieval for all collectors in the group by calling
    /// their `start()` function. Collectors failing to start the event
    /// retrieval will be kept in the group.
    pub(crate) fn start(&mut self, _: &CliConfig) -> Result<()> {
        let section_factories = match self.section_factories.take() {
            Some(factories) => factories,
            None => bail!("No section factory found, aborting"),
        };

        self.factory.start(section_factories)?;
        self.probes.attach()?;

        for (id, c) in self.list.iter_mut() {
            if c.start().is_err() {
                warn!("Could not start '{}'", id);
            }
        }

        Ok(())
    }

    /// Starts the processing loop and block until we get a single SIGINT
    /// (e.g. ctrl+c), then return after properly cleaning up. This is the main
    /// collector cmd loop.
    pub(crate) fn process(&mut self, cli: &CliConfig) -> Result<()> {
        let collect = cli
            .subcommand
            .as_any()
            .downcast_ref::<Collect>()
            .ok_or_else(|| anyhow!("wrong subcommand"))?;

        // We use JSON format output for all events for now.
        let mut json = JsonFormat::default();
        let mut processors = get_processors(&mut json, collect.args()?)?;

        let mut sigint = Signals::new([SIGINT])?;
        let (txc, rxc) = mpsc::channel();

        thread::spawn(move || {
            // Only wait for a single SIGINT to let the user really interrupt us
            // in case it's needed.
            sigint.wait();
            info!("Received SIGINT, terminating...");

            if let Err(e) = txc.send(()) {
                error!(
                    "Failed to send message after receiving ctrl+c signal: {}",
                    e
                );
            }
        });

        loop {
            match self.factory.next_event(Some(Duration::from_secs(1)))? {
                Some(event) => processors
                    .iter_mut()
                    .try_for_each(|p| p.process_one(&event))?,
                None => continue,
            }

            // If we're interrupted, break the loop to allow nicely exiting.
            if rxc.try_recv().is_ok() {
                break;
            }
        }

        processors.iter_mut().try_for_each(|p| p.flush())
    }

    /// Parse a user defined probe (through cli parameters) and extract its type and
    /// target.
    fn parse_probe(&self, probe: &str) -> Result<Probe> {
        let (type_str, target) = match probe.split_once(':') {
            Some((type_str, target)) => (type_str, target),
            None => {
                info!(
                    "Invalid probe format, no TYPE given in '{}', using 'kprobe:{}'. See the help.",
                    probe, probe
                );
                ("kprobe", probe)
            }
        };

        let symbol = Symbol::from_name(target)?;

        // Check if the probe would be used by a collector to retrieve data.
        let mut valid = false;
        for r#type in self.known_kernel_types.iter() {
            if symbol.parameter_offset(r#type)?.is_some() {
                valid = true;
                break;
            }
        }
        if !valid {
            warn!(
                "A probe to symbol {} is attached but no collector will retrieve data from it, only generic information will be retrieved",
                symbol
            );
        }

        match type_str {
            "kprobe" => Ok(Probe::kprobe(symbol)?),
            "kretprobe" => Ok(Probe::kretprobe(symbol)?),
            "tp" => Ok(Probe::raw_tracepoint(symbol)?),
            x => bail!("Invalid TYPE {}. See the help.", x),
        }
    }
}

/// Allocate collectors and retrieve a group containing them, used to perform
/// batched operations. This is the primary entry point for manipulating the
/// collectors.
pub(crate) fn get_collectors() -> Result<Group> {
    let factory = BpfEventsFactory::new()?;
    let event_map_fd = factory.map_fd();
    let mut group = Group::new(Box::new(factory))?;

    group.probes.reuse_map("events_map", event_map_fd)?;

    // Register all collectors here.
    group
        .register(
            ModuleId::SkbTracking,
            Box::new(SkbTrackingCollector::new()?),
            Box::<SkbTrackingEvent>::default(),
        )?
        .register(
            ModuleId::Skb,
            Box::new(SkbCollector::new()?),
            Box::<SkbEvent>::default(),
        )?
        .register(
            ModuleId::Ovs,
            Box::new(OvsCollector::new()?),
            Box::<OvsEvent>::default(),
        )?;

    Ok(group)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{
        cli::{MainConfig, SubCommand},
        core::events::{bpf::BpfRawSection, *},
    };
    use crate::{EventSection, EventSectionFactory};

    struct DummyCollectorA;
    struct DummyCollectorB;

    impl Collector for DummyCollectorA {
        fn new() -> Result<DummyCollectorA> {
            Ok(DummyCollectorA)
        }
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            Some(vec!["struct sk_buff *", "struct net_device *"])
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::ProbeManager) -> Result<()> {
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
        fn known_kernel_types(&self) -> Option<Vec<&'static str>> {
            None
        }
        fn register_cli(&self, _: &mut DynamicCommand) -> Result<()> {
            Ok(())
        }
        fn init(&mut self, _: &CliConfig, _: &mut probe::ProbeManager) -> Result<()> {
            bail!("Could not initialize")
        }
        fn start(&mut self) -> Result<()> {
            bail!("Could not start");
        }
    }

    #[derive(Default, Deserialize, Serialize, EventSection, EventSectionFactory)]
    struct TestEvent {}

    impl RawEventSectionFactory for TestEvent {
        fn from_raw(&mut self, _: Vec<BpfRawSection>) -> Result<Box<dyn EventSection>> {
            Ok(Box::new(TestEvent::default()))
        }
    }

    #[test]
    fn register_collectors() -> Result<()> {
        let mut group = Group::new(Box::new(BpfEventsFactory::new()?))?;
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        assert!(group
            .register(
                ModuleId::Ovs,
                Box::new(DummyCollectorB::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        Ok(())
    }

    #[test]
    fn register_uniqueness() -> Result<()> {
        let mut group = Group::new(Box::new(BpfEventsFactory::new()?))?;
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_ok());
        assert!(group
            .register(
                ModuleId::Skb,
                Box::new(DummyCollectorA::new()?),
                Box::<TestEvent>::default(),
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn get_collectors() {
        assert!(super::get_collectors().is_ok());
    }

    #[test]
    fn init_collectors() -> Result<()> {
        let config = CliConfig {
            main_config: MainConfig::default(),
            subcommand: Box::new(Collect::new()?),
        };
        let mut group = Group::new(Box::new(BpfEventsFactory::new()?))?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        let mut mgr = probe::ProbeManager::new()?;

        assert!(dummy_a.init(&config, &mut mgr).is_ok());
        assert!(dummy_b.init(&config, &mut mgr).is_err());
        assert!(group.init(&config).is_ok());
        Ok(())
    }

    #[test]
    fn start_collectors() -> Result<()> {
        let config = CliConfig {
            main_config: MainConfig::default(),
            subcommand: Box::new(Collect::new()?),
        };
        let mut group = Group::new(Box::new(BpfEventsFactory::new()?))?;
        let mut dummy_a = Box::new(DummyCollectorA::new()?);
        let mut dummy_b = Box::new(DummyCollectorB::new()?);

        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        assert!(dummy_a.start().is_ok());
        assert!(dummy_b.start().is_err());
        assert!(group.start(&config).is_ok());
        Ok(())
    }

    #[test]
    fn parse_probe() -> Result<()> {
        let mut group = Group::new(Box::new(BpfEventsFactory::new()?))?;
        group.register(
            ModuleId::Skb,
            Box::new(DummyCollectorA::new()?),
            Box::<TestEvent>::default(),
        )?;
        group.register(
            ModuleId::Ovs,
            Box::new(DummyCollectorB::new()?),
            Box::<TestEvent>::default(),
        )?;

        // Valid probes.
        assert!(group.parse_probe("consume_skb").is_ok());
        assert!(group.parse_probe("kprobe:kfree_skb_reason").is_ok());
        assert!(group.parse_probe("tp:skb:kfree_skb").is_ok());

        // Invalid probe: symbol does not exist.
        assert!(group.parse_probe("foobar").is_err());
        assert!(group.parse_probe("kprobe:foobar").is_err());
        assert!(group.parse_probe("tp:42:foobar").is_err());

        // Invalid probe: wrong TYPE.
        assert!(group.parse_probe("kprobe:skb:kfree_skb").is_err());
        assert!(group.parse_probe("skb:kfree_skb").is_err());
        assert!(group.parse_probe("foo:kfree_skb").is_err());

        // Invalid probe: empty parts.
        assert!(group.parse_probe("").is_err());
        assert!(group.parse_probe("kprobe:").is_err());
        assert!(group.parse_probe("tp:").is_err());
        assert!(group.parse_probe("tp:skb:").is_err());
        assert!(group.parse_probe(":kfree_skb_reason").is_err());

        Ok(())
    }
}
