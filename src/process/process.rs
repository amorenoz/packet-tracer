#![allow(dead_code)] // FIXME
use std::{
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use log::error;

use crate::{
    core::{
        events::{Event, EventFactory, SectionFactories},
        signals::Running,
    },
    output::Output,
};

/// Trait to process events
pub(crate) trait ProcessorAction: Send {
    /// Process an event and generate an Vector of events.
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>>;
    /// Stop processing. Remaining events can be returned.
    fn stop(&mut self) -> Result<Vec<Event>>;
}

/// ProcessStage is a wrapper around a ProcessorAction that handles input & output of events via
/// mpsc channels.
struct ProcessorStage {
    name: String,
    action: Option<Box<dyn ProcessorAction>>,
    input: Option<Receiver<Event>>,
    output_tx: Sender<Event>,
    output_rx: Option<Receiver<Event>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ProcessorStage {
    /// Create a new named Stage with a ProcessorAction
    fn new(name: String, action: Box<dyn ProcessorAction>) -> Result<Self> {
        let (output_tx, output_rx) = channel();
        Ok(Self {
            name,
            action: Some(action),
            input: None,
            output_tx,
            output_rx: Some(output_rx),
            thread: None,
        })
    }

    /// Chain a processor with the next one
    fn chain(&mut self, next: &mut ProcessorStage) -> Result<()> {
        if let Some(out) = self.output_rx.take() {
            next.input = Some(out);
        } else {
            bail!("stage already chained");
        }
        Ok(())
    }

    /// Stop the processor. Join the thread.
    fn stop(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|e| anyhow!("Failed to join thread {e:?}"))?;
        }
        Ok(())
    }

    /// Start the stage thread.
    fn start(&mut self) -> Result<()> {
        let input = match self.input.take() {
            Some(input) => input,
            None => bail!(
                "{}: stage has no input. Chain it with some previous stage",
                self.name
            ),
        };

        let sink = self.output_rx.is_some();
        let output = self.output_tx.clone();
        let mut action = match self.action.take() {
            Some(action) => action,
            None => bail!("action not set"),
        };
        let name = self.name.clone();

        self.thread = Some(
            thread::Builder::new()
                .name(self.name.clone())
                .spawn(move || {
                    while let Ok(event) = input.recv() {
                        match action.process_one(event) {
                            Ok(mut result) => {
                                if sink {
                                    continue;
                                }
                                for event in result.drain(..) {
                                    if let Err(e) = output.send(event) {
                                        error!("{name}: Error sending event to next stage {e}");
                                    }
                                }
                            }
                            Err(e) => error!("{name}: Failed to process event {e}"),
                        }
                    }
                    if let Err(e) = action.stop() {
                        error!("{name}: Failed to stop processing events {e}")
                    }
                })?,
        );
        Ok(())
    }
}

/// A ProcessorStage made of a set of Outputs
#[derive(Default)]
struct OutputStage {
    outputs: Vec<Box<dyn Output + 'static>>,
}

impl OutputStage {
    /// Create an output stage from a vector of Outputs. Note the vector is consumed and object's
    /// ownership is moved.
    fn from(out: &mut Vec<Box<dyn Output + 'static>>) -> Self {
        let mut outputs = Vec::<Box<dyn Output>>::default();
        outputs.append(out);

        Self { outputs }
    }
}

impl ProcessorAction for OutputStage {
    fn process_one(&mut self, e: Event) -> Result<Vec<Event>> {
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
    stages: Vec<ProcessorStage>,
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
    pub(crate) fn add_stage(
        &mut self,
        name: String,
        action: Box<dyn ProcessorAction + Send>,
    ) -> Result<()> {
        let mut stage = ProcessorStage::new(name, action)?;
        if let Some(last) = self.stages.last_mut() {
            last.chain(&mut stage)?;
        }
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
        self.add_stage("output".to_string(), Box::new(output_stage))?;

        // Start the factory
        self.source.start(factories)?;

        {
            // Create the initial channel. Used by the main loop to send events to the first processor
            // in the chain.
            let (first_tx, first_rx) = channel();
            match self.stages.first_mut() {
                Some(first) => first.input = Some(first_rx),
                None => bail!("No processors configured"),
            }

            // Start all processors
            for stage in self.stages.iter_mut() {
                stage.start()?;
            }

            // Main loop:
            while state.running() {
                match self.source.next_event(Some(self.duration))? {
                    Some(event) => first_tx.send(event)?,
                    None => continue,
                }
            }
        }
        // First channel is closed so all the processors start receiving a hang up and closing.
        // Join all processors
        for stage in self.stages.iter_mut() {
            stage.stop()?;
        }
        Ok(())
    }
}
