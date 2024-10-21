use anyhow::{bail, Result};

use crate::core::{
    kernel::symbol::{matching_events_to_symbols, matching_functions_to_symbols, Symbol},
    probe::Probe,
};

/// Parse a user defined probe (through cli parameters) and extract its type and
/// target. Filter results using symbols.
pub(crate) fn parse_probe<F>(probe: &str, filter: F) -> Result<Vec<Probe>>
where
    F: Fn(&Symbol) -> bool,
{
    // We only need a lightweight version of `ProbeType` here; this simplifies
    // the below logic.
    enum ProbeType {
        Kprobe,
        Kretprobe,
        RawTracepoint,
    }
    use ProbeType::*;

    let (r#type, target) = match probe.split_once(':') {
        Some((type_str, target)) => match type_str {
            "kprobe" | "k" => (Kprobe, target),
            "kretprobe" | "kr" => (Kretprobe, target),
            "raw_tracepoint" | "tp" => (RawTracepoint, target),
            // If a single ':' was found in the probe name but we didn't match
            // any known type, defaults to trying using it as a raw tracepoint.
            _ if probe.chars().filter(|c| *c == ':').count() == 1 => (RawTracepoint, probe),
            x => bail!("Invalid TYPE {}. See the help.", x),
        },
        // If no ':' was found, defaults to kprobe.
        None => (Kprobe, probe),
    };

    // Convert the target to a list of matching ones for probe types
    // supporting it.
    let mut symbols = match r#type {
        Kprobe | Kretprobe => matching_functions_to_symbols(target)?,
        RawTracepoint => matching_events_to_symbols(target)?,
    };

    let mut probes = Vec::new();
    for symbol in symbols.drain(..) {
        // Check if the symbol matches the filter.
        if !filter(&symbol) {
            continue;
        }

        probes.push(match r#type {
            Kprobe => Probe::kprobe(symbol)?,
            Kretprobe => Probe::kretprobe(symbol)?,
            RawTracepoint => Probe::raw_tracepoint(symbol)?,
        })
    }

    Ok(probes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_probe() {
        let filter = |_: &_| true;

        // Valid probes.
        assert!(super::parse_probe("consume_skb", filter).is_ok());
        assert!(super::parse_probe("kprobe:kfree_skb_reason", filter).is_ok());
        assert!(super::parse_probe("k:kfree_skb_reason", filter).is_ok());
        assert!(super::parse_probe("skb:kfree_skb", filter).is_ok());
        assert!(super::parse_probe("tp:skb:kfree_skb", filter).is_ok());
        assert!(super::parse_probe("tcp_v6_*", filter).is_ok());
        assert!(super::parse_probe("kprobe:tcp_v6_*", filter).is_ok());
        assert!(!super::parse_probe("kprobe:tcp_v6_*", filter)
            .unwrap()
            .is_empty());
        assert!(super::parse_probe("kretprobe:tcp_*", filter).is_ok());
        assert!(super::parse_probe("kr:tcp_*", filter).is_ok());
        assert!(super::parse_probe("tp:skb:kfree_*", filter).is_ok());
        assert!(super::parse_probe("tp:*skb*", filter).is_ok());

        // Invalid probe: symbol does not exist.
        assert!(super::parse_probe("foobar", filter).is_err());
        assert!(super::parse_probe("kprobe:foobar", filter).is_err());
        assert!(super::parse_probe("tp:42:foobar", filter).is_err());
        assert!(super::parse_probe("tp:kfree_*", filter).is_err());
        assert!(super::parse_probe("*foo*", filter).is_err());

        // Invalid probe: wrong TYPE.
        assert!(super::parse_probe("kprobe:skb:kfree_skb", filter).is_err());
        assert!(super::parse_probe("foo:kfree_skb", filter).is_err());

        // Invalid probe: empty parts.
        assert!(super::parse_probe("", filter).is_err());
        assert!(super::parse_probe("kprobe:", filter).is_err());
        assert!(super::parse_probe("tp:", filter).is_err());
        assert!(super::parse_probe("tp:skb:", filter).is_err());
        assert!(super::parse_probe(":kfree_skb_reason", filter).is_err());
    }
}
