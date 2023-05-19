#![allow(dead_code)] // FIXME
use std::time::Duration;

use anyhow::{bail, Result};
use log::{debug, error};

use crate::{
    core::{
        events::{Event, EventFactory, SectionFactories},
        signals::Running,
    },
    output::Output,
};

/// Trait to process events and send them to the next ProcessorStage.
pub(crate) trait ProcessorStage: {
    /// Process an event and generate an Vector of events.
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>>;
    /// Stop processing. Remaining events can be returned.
    fn stop(&mut self) -> Result<Vec<Event>>;
}

/// A ProcessorStage made of a set of Outputs
#[derive(Default)]
struct OutputStage {
    outputs: Vec<Box<dyn Output + 'static>>
}

impl OutputStage {
    /// Create an output stage from a vector of Outputs. Note the vector is consumed and object's
    /// ownership is moved.
    fn from(out: &mut Vec<Box<dyn Output + 'static>>) -> Self {
        let mut outputs =  Vec::<Box<dyn Output>>::default();
        outputs.append(out);
        
        Self {
            outputs
        }
    }
}

impl ProcessorStage for OutputStage {
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>> {
        debug!("processing one");
        debug!("number of outputs: {}", self.outputs.len());
        for o in self.outputs.iter_mut() {
            o.output_one(&e)?;
        }
        Ok(Vec::new())
    }
    fn stop(&mut self) -> Result<Vec<Event>> {
        for o in self.outputs.iter_mut() {
            o.flush()?;
        }
        Ok(Vec::new())
    }
}

/// PostProcessor is a small utility object capable of reading files form a file
/// and sending them to a number of processors in an organized way.
pub(crate) struct Processor<'a, F>
where
    F: EventFactory,
{
    source: &'a mut F,
    stages: Vec<Box<dyn ProcessorStage>>,
    output: Vec<Box<dyn Output>>,
    duration: Duration,
}

impl<'a, F> Processor<'a, F>
where
    F: EventFactory,
{
    /// Create a new PostProcessor on a file.
    pub(crate) fn new(source: &'a mut F) -> Result<Self> {
        Ok(Processor {
            source,
            stages: Vec::new(),
            output: Vec::new(),
            duration: Duration::from_secs(1),
        })
    }

    /// Add a processor stage.
    pub(crate) fn add_stage(&mut self, stage: Box<dyn ProcessorStage>) -> Result<()> {
        self.stages.push(stage);
        Ok(())
    }

    /// Add output
    pub(crate) fn add_output(&mut self, output: Box<dyn Output>) -> Result<()> {
        self.output.push(output);
        Ok(())
    }

    pub(crate) fn set_duration(&mut self, duration: Duration) -> Result<()> {
        self.duration = duration;
        Ok(())
    }

    /// Start processing
    pub(crate) fn run(&'a mut self, state: Running, factories: SectionFactories) -> Result<()> {
        // Insert outputs as last Processor.
        let output_stage = OutputStage::from(&mut self.output);
        self.stages.push(Box::new(output_stage));

        // Start the factory
        self.source.start(factories)?;

        // Main loop:
        while state.running() {
            let mut events = Vec::new(); 

            match self.source.next_event(Some(self.duration))? {
                Some(event) => {
                    events.push(event);
                }
                None => continue,
            }

            for (idx, stage) in self.stages.iter_mut().enumerate() {
                let mut result = Vec::new();
                for event in events.drain(..) {
                    result.append(&mut stage.process_one(event)?);
                }
                events = result;
            }
        }
        Ok(())
    }
}
