//! Advisory observation of this process only.

use std::fs::File;
use std::io::Read;

use super::Observation;

const STATUS_MAX: usize = 16 * 1024;

pub fn tracer_attachment() -> Observation {
    let Ok(file) = File::open("/proc/self/status") else {
        return Observation::Inconclusive;
    };
    let mut status = Vec::new();
    if file
        .take(STATUS_MAX as u64 + 1)
        .read_to_end(&mut status)
        .is_err()
        || status.len() > STATUS_MAX
    {
        return Observation::Inconclusive;
    }
    parse(&status)
}

fn parse(status: &[u8]) -> Observation {
    let mut tracer = status
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"TracerPid:"));
    let Some(value) = tracer.next() else {
        return Observation::Inconclusive;
    };
    if tracer.next().is_some() {
        return Observation::Inconclusive;
    }
    match std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
    {
        Some(0) => Observation::NotObservedWithinScope,
        Some(_) => Observation::Observed,
        None => Observation::Inconclusive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_status_uses_one_exact_tracer_field() {
        assert_eq!(
            parse(b"Name:\tvmk\nTracerPid:\t0\n"),
            Observation::NotObservedWithinScope
        );
        assert_eq!(parse(b"TracerPid:\t12\n"), Observation::Observed);
        for status in [
            b"TracerPid:\t0\nTracerPid:\t12\n".as_slice(),
            b"TracerPid:\tx\n",
            b"TracerPidx: 12\n",
        ] {
            assert_eq!(parse(status), Observation::Inconclusive);
        }
    }
}
