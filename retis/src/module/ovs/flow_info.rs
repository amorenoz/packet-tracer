//! OpenvSwitch flow information enrichment.
//!
//! The OpenvSwitch datapath is made of flows which are comprised of
//! a match and a list actions. They are uniquely identified by a unique
//! flow id, or UFID.
//!
//! Each of these datapath flows are built as a result of the OpenFlow rule
//! classification which typically involves many OpenFlow rules. Therefore,
//! each datapath flow is the result of several OpenFlow rules being matched.
//!
//! OpenvSwitch 3.4 supports extracting the OpenFlow flows that contributed to
//! the creation of each datapath flow through a unixctl command called
//! "ofproto/detrace".
//!
//! This module implements a thread that can query OpenvSwitch for this information
//! (caching the results) and enrich the event file with this relationship.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use log::{debug, error, warn};
use ovs_unixctl::OvsUnixCtl;

use crate::core::events::factory::RetisEventsFactory;
use crate::events::*;
use crate::helpers::signals::Running;

const MAX_REQUESTS_PER_SEC: u64 = 10;

pub(crate) struct FlowEnricher {
    // Factory to use for event creation
    events_factory: Arc<RetisEventsFactory>,
    // Thread handle
    thread: Option<thread::JoinHandle<()>>,
    // Whether ofproto/detrace is supported
    detrace_supported: bool,

    // Sender and receiver of the channel that is used to request enrichments
    sender: mpsc::Sender<Ufid>,
    receiver: Option<mpsc::Receiver<Ufid>>,
}

impl FlowEnricher {
    pub(crate) fn new(events_factory: Arc<RetisEventsFactory>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<Ufid>();

        let mut unixctl = OvsUnixCtl::new()?;
        let commands = unixctl
            .list_commands()
            .map_err(|e| anyhow!("cannot connect OVS: {e}"))?;

        Ok(FlowEnricher {
            events_factory,
            thread: None,
            sender,
            receiver: Some(receiver),
            detrace_supported: commands.iter().any(|(c, _)| c == "ofproto/detrace"),
        })
    }

    pub(crate) fn detrace_supported(&self) -> bool {
        self.detrace_supported
    }

    pub(crate) fn sender(&self) -> &mpsc::Sender<Ufid> {
        &self.sender
    }

    pub(crate) fn start(&mut self, state: Running) -> Result<()> {
        let detrace_supported = self.detrace_supported;
        let factory = self.events_factory.clone();
        let receiver = self
            .receiver
            .take()
            .ok_or_else(|| anyhow!("ovs-flow-enricher: ufid receiver not available"))?;

        let mut unixctl = OvsUnixCtl::new()?;
        self.thread = Some(
            thread::Builder::new()
                .name("ovs-flow-enricher".into())
                .spawn(move || {
                    let mut tasks: VecDeque<Ufid> = VecDeque::new();
                    let mut next_request = SystemTime::UNIX_EPOCH;
                    let mut wait_time = Duration::from_millis(500);

                    let min_request_time = Duration::from_millis(1000 / MAX_REQUESTS_PER_SEC);

                    while state.running() {
                        use mpsc::RecvTimeoutError::*;
                        match receiver.recv_timeout(wait_time) {
                            Ok(ufid) => tasks.push_back(ufid),
                            Err(Disconnected) => break,
                            Err(Timeout) => (),
                        }

                        // Nothing to do.
                        if tasks.is_empty() {
                            wait_time = Duration::from_millis(500);
                            continue;
                        }

                        let now = SystemTime::now();

                        // Too soon for another request.
                        if now < next_request {
                            wait_time = next_request.duration_since(now).unwrap();
                            debug!(
                                "ovs-flow-enricher: Delaying requests to OVS for another {} ms",
                                wait_time.as_millis()
                            );
                            continue;
                        }
                        next_request = now + min_request_time;

                        // We checked tasks was not empty before.
                        let ufid = tasks.pop_front().unwrap();
                        let ufid_str = format!("ufid:{}", ufid);

                        debug!(
                            "ovs-flow-enricher: Enriching flow. Pending enrichment tasks {}",
                            tasks.len()
                        );
                        let ofpflows = if detrace_supported {
                            match unixctl.run("ofproto/detrace", &[ufid_str.as_str()]) {
                                Err(e) => {
                                    error!("ovs-flow-enricher: failed to detrace flow {e}");
                                    continue;
                                }
                                Ok(None) => {
                                    // If the datapath flow was removed before enrichment this
                                    // could happen.
                                    warn!("ovs-flow-enricher: ofproto/detrace returned empty data");
                                    continue;
                                }
                                Ok(Some(data)) => data.lines().map(String::from).collect(),
                            }
                        } else {
                            Vec::new()
                        };

                        let dpflow = match unixctl.run("dpctl/get-flow", &[ufid_str.as_str()]) {
                            Err(e) => {
                                error!("ovs-flow-enricher: failed to get flow {e}");
                                continue;
                            }
                            Ok(None) => {
                                // If the datapath flow was removed before enrichment this
                                // could happen.
                                warn!("ovs-flow-enricher: dpctl/get-flow returned empty data");
                                continue;
                            }
                            Ok(Some(data)) => String::from(data.trim()),
                        };

                        if let Err(e) = factory.add_event(fill_event(ufid, dpflow, ofpflows)) {
                            error!("ovs-flow-enricher failed to add event {e}");
                        }
                    }
                })?,
        );
        Ok(())
    }

    pub(crate) fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|e| anyhow!("Failed to join othread ovs-flow-enricher: {e:?}"))
        } else {
            Ok(())
        }
    }
}

fn fill_event(
    ufid: Ufid,
    dpflow: String,
    ofpflows: Vec<String>,
) -> impl Fn(&mut Event) -> Result<()> {
    move |event| -> Result<()> {
        event.insert_section(
            SectionId::OvsFlowInfo,
            Box::new(OvsFlowInfoEvent {
                ufid,
                dpflow: dpflow.clone(),
                ofpflows: ofpflows.clone(),
            }),
        )
    }
}
