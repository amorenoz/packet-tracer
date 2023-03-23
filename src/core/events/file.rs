use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Result};

use crate::{core::events::*, module::ModuleId};

/// Events factory reading from a file.
pub(crate) struct FileEventsFactory {
    path: PathBuf,
    lines: Option<Lines<BufReader<File>>>,
    section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>>,
}

impl FileEventsFactory {
    pub(crate) fn new(path: &Path) -> Self {
        FileEventsFactory {
            path: path.to_path_buf(),
            lines: None,
            section_factories: HashMap::new(),
        }
    }
}

impl EventFactory for FileEventsFactory {
    fn start(
        &mut self,
        section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>>,
    ) -> Result<()> {
        self.lines = Some(BufReader::new(File::open(&self.path)?).lines());
        self.section_factories = section_factories;
        Ok(())
    }

    fn next_event(&mut self, _: Option<Duration>) -> Result<Option<Event>> {
        Ok(match &mut self.lines {
            Some(lines) => match lines.next() {
                Some(Ok(line)) => Some(parse_line(&line, &mut self.section_factories)?),
                _ => None,
            },
            None => bail!("FileEventsFactory wasn't started"),
        })
    }
}

fn parse_line(
    data: &str,
    factories: &mut HashMap<ModuleId, Box<dyn EventSectionFactory>>,
) -> Result<Event> {
    let json: serde_json::Value = serde_json::from_str(data)?;
    let obj = match json.as_object() {
        Some(obj) => obj,
        _ => bail!("First level of an event must be a json object"),
    };

    let mut event = Event::new();
    for (section, val) in obj.iter() {
        let id = ModuleId::from_str(section)?;

        let factory = match factories.get(&id) {
            Some(factory) => factory,
            None => bail!("Unknown factory for event section owner {}", id),
        };

        event.insert_section(id, factory.from_json(val.clone())?)?;
    }

    Ok(event)
}
