#![allow(dead_code)] // FIXME
use crate::core::probe::user::proc::UsdtNote;
//
// TODO merge with kernel probes
/// Probes types supported by this crate.
#[derive(Debug)]
pub(crate) enum UProbe {
    Uprobe,
    Usdt(UsdtNote),
    Max,
}
