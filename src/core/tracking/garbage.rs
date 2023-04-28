//! # Tracking garbage collector
//!
//! When modules track packets or other structurs using ebpf maps,
//! loosing events might some enties stale.
//!
//! This module provides a utility object that can take care of removeing
//! stale entries

use std::{collections::HashMap, ops::Fn, sync::Arc, thread, time::Duration};

use crate::core::workaround::SendableMap;
use anyhow::Result;
use log::{debug, error, warn};
use nix::time;

pub(crate) struct TrackingGC {
    // Maps to track
    maps: Option<HashMap<String, SendableMap>>,
    // Duration extraction function. Based on the value of the map, it returns
    // the duration of the entry.
    extract_age: Arc<dyn Fn(Vec<u8>) -> Result<Duration> + Send + Sync + 'static>,
    // Interval of GC runs
    interval: u64,
    // Maximum age of entries. Older entires will be removed
    limit: u64,
    // The name of the thread
    name: String,

    thread: Option<thread::JoinHandle<()>>,
}

impl TrackingGC {
    // 5 seconds
    const DEFAULT_OLD_LIMIT: u64 = 60;
    // 60 seconds
    const DEFAULT_INTERVAL: u64 = 5;

    pub(crate) fn new<F>(mut maps: HashMap<&'static str, libbpf_rs::Map>, extract_age: F) -> Self
    where
        F: Fn(Vec<u8>) -> Result<Duration> + Send + Sync + 'static,
    {
        TrackingGC {
            maps: Some(
                maps.drain()
                    .map(|(n, m)| (n.to_string(), SendableMap::from(m)))
                    .collect(),
            ),
            extract_age: Arc::new(extract_age),
            interval: Self::DEFAULT_INTERVAL,
            limit: Self::DEFAULT_OLD_LIMIT,
            name: "tracking_gc".to_string(),
            thread: None,
        }
    }

    pub(crate) fn interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    pub(crate) fn limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }

    pub(crate) fn name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub(crate) fn run(&mut self) -> Result<()> {
        let interval = self.interval;
        let limit = self.limit;
        let mut maps = self.maps.take().unwrap();
        let extract_age = self.extract_age.clone();
        self.thread = Some(thread::Builder::new().name(self.name.clone()).spawn(move || {
            loop {
                // Let's run every interval seconds.
                thread::sleep(Duration::from_secs(interval));
                let now = Duration::from(time::clock_gettime(time::ClockId::CLOCK_MONOTONIC).unwrap());

                // Loop through the tracking map entries and see if we see old
                // ones we should remove manually.
                for (name, map) in maps.iter_mut() {
                    let map = map.get_mut();
                    let mut to_remove = Vec::new();
                    for key in map.keys() {
                        if let Ok(Some(raw)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                            // Get the Duration associated with the entry.
                            let age = match (extract_age)(raw) {
                                Ok(age) => age,
                                Err(e) => {
                                    error!("{name}: entry age extraction failed for key {:#x?}: {e}", key);
                                    continue;
                                }
                            };
                            debug!("{name} key found with age {}", age.as_nanos());
                            if now.saturating_sub(age)
                                > Duration::from_secs(limit)
                            {
                                to_remove.push(key);
                            }
                        }
                    }
                    // Actually remove the outdated entries and issue a warning as
                    // while it can be expected, it should not happen too often.
                    for key in to_remove {
                        map.delete(&key).ok();
                        warn!("Removed old entry from {name} tracking map: {:x?}", key);
                    }
                }
            }
        }
      )?);
        Ok(())
    }
}
