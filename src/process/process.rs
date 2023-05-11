#![allow(dead_code)] // FIXME
use std::time::Duration;

use anyhow::{bail, Result};

use crate::{
    core::{
        events::{Event, EventFactory, SectionFactories},
        signals::Running,
    },
    output::Output,
};

/// Trait to process events and send them to the next ProcessorStage.
pub(crate) trait ProcessorStage {
    /// Set the next ProcessorStage
    fn set_next(&mut self, b: Box<dyn ProcessorStage>) -> Result<()>;
    /// Process and output events one by one.
    fn process_one(&mut self, e: &Event) -> Result<()>;
    /// Stop processing. Procesor stages must propagate the stop() action.
    fn stop(&mut self) -> Result<()>;
}

/// PostProcessor is a small utility object capable of reading files form a file
/// and sending them to a number of processors in an organized way.
pub(crate) struct Processor<'a, F>
where
    F: EventFactory,
{
    source: &'a mut F,
    head: Option<Box<dyn ProcessorStage>>,
    output: Vec<Box<dyn Output>>,
    duration: Duration,
}

// Implement a default final stage that outputs the events to the configured output.
impl<'a, F> ProcessorStage for Processor<'a, F>
where
    F: EventFactory,
{
    fn set_next(&mut self, _: Box<dyn ProcessorStage>) -> Result<()> {
        bail!("not implemented")
    }

    fn process_one(&mut self, e: &Event) -> Result<()> {
        for output in self.output.iter_mut() {
            output.output_one(e)?;
        }
        Ok(())
    }
    /// Flush any pending output operations.
    fn stop(&mut self) -> Result<()> {
        for output in self.output.iter_mut() {
            output.flush()?;
        }
        Ok(())
    }
}

impl<'a, F> Processor<'a, F>
where
    F: EventFactory,
{
    /// Create a new PostProcessor on a file.
    pub(crate) fn new(source: &'a mut F) -> Result<Self> {
        Ok(Processor {
            source,
            head: None,
            output: Vec::new(),
            duration: Duration::from_secs(1),
        })
    }

    /// Add a processor stage.
    pub(crate) fn add_stage(&mut self, stage: Box<dyn ProcessorStage>) -> Result<()> {
        if let Some(mut head) = self.head.take() {
            head.set_next(stage)?;
        } else {
            self.head = Some(stage);
        }
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
    pub(crate) fn run(&mut self, state: Running, factories: SectionFactories) -> Result<()> {
        self.source.start(factories)?;

        while state.running() {
            match self.source.next_event(Some(self.duration))? {
                Some(event) => {
                    if let Some(mut head) = self.head.take() {
                        head.process_one(&event)?;
                    }
                }
                None => continue,
            }
        }
        if let Some(mut head) = self.head.take() {
            head.stop()?;
        }
        Ok(())
    }
}
