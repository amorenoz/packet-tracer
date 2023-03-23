use std::collections::HashMap;

use anyhow::{bail, Result};

use super::{
    ovs::{OvsCollector, OvsEvent},
    skb::{SkbCollector, SkbEvent},
    skb_tracking::{SkbTrackingCollector, SkbTrackingEvent},
    *,
};
use crate::{
    collect::Collector,
    core::{
        events::{bpf::CommonEvent, *},
        probe::kernel::KernelEvent,
    },
};

/// Group of modules; used to handle a set of modules. Module "registration"
/// happens there. We expect a single Group object when running the program.
pub(crate) struct Group {
    /// Set of registered modules we can use.
    pub(crate) modules: HashMap<ModuleId, Box<dyn Collector>>,
    /// Factory used to retrieve events.
    pub(crate) factory: Box<dyn EventFactory>,
    /// Event section factories to parse sections into an event. Section
    /// factories come from modules.
    pub(crate) section_factories: Option<HashMap<ModuleId, Box<dyn EventSectionFactory>>>,
}

impl Group {
    pub(crate) fn new(factory: Box<dyn EventFactory>) -> Result<Group> {
        let mut section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>> = HashMap::new();

        section_factories.insert(ModuleId::Common, Box::<CommonEvent>::default());
        // FIXME: provide stack map in a way
        section_factories.insert(ModuleId::Kernel, Box::<KernelEvent>::default());

        Ok(Group {
            modules: HashMap::new(),
            factory,
            section_factories: Some(section_factories),
        })
    }

    /// Register a collector to the group.
    ///
    /// ```
    /// group
    ///     .register(
    ///         Box::new(FirstCollector::new()?,
    ///         Box::<FirstEvent>::default()))?,
    ///     )?
    ///     .register(
    ///         Box::new(SecondCollector::new()?,
    ///         Box::<SecondEvent>::default()))?,
    ///     )?;
    /// ```
    pub(crate) fn register(
        &mut self,
        id: ModuleId,
        collector: Box<dyn Collector>,
        section_factory: Box<dyn EventSectionFactory>,
    ) -> Result<&mut Self> {
        // Ensure uniqueness of the collector name. This is important as their
        // name is used as a key.
        if self.modules.get(&id).is_some() {
            bail!(
                "Could not insert collector '{}'; name already registered",
                id,
            );
        }

        match &mut self.section_factories {
            Some(factories) => factories.insert(id, section_factory),
            None => bail!("Section factories map no found"),
        };

        self.modules.insert(id, collector);
        Ok(self)
    }

    /// Start the event retrieval in the factory.
    pub(crate) fn start_factory(&mut self) -> Result<()> {
        let section_factories = match self.section_factories.take() {
            Some(factories) => factories,
            None => bail!("No section factory found, aborting"),
        };

        self.factory.start(section_factories)
    }

    /// Sometimes we need to perform actions on factories at a higher level.
    /// It's a bit of an hack for now, it would be good to remove it. One option
    /// would be to move the core EventSection and their factories into modules
    /// directly (using mandatory modules). This should not affect the module
    /// API though, so it should be fine as-is for now.
    #[cfg(not(test))]
    pub(crate) fn get_section_factory<T: EventSectionFactory + 'static>(
        &mut self,
        id: ModuleId,
    ) -> Option<&mut T> {
        match self.section_factories.as_mut() {
            Some(section_factories) => match section_factories.get_mut(&id) {
                Some(module) => module.as_any_mut().downcast_mut::<T>(),
                None => None,
            },
            None => None,
        }
    }
}

pub(crate) fn get_modules(factory: Box<dyn EventFactory>) -> Result<Group> {
    let mut group = Group::new(factory)?;

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
    use crate::core::events::bpf::BpfEventsFactory;

    #[test]
    fn get_modules() {
        let factory = BpfEventsFactory::new().unwrap();
        assert!(super::get_modules(Box::new(factory)).is_ok());
    }
}
