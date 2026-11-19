//! IPv4 address anonymization for byte streams.

use alloc::vec::Vec;
use core::ops::Range;

/// The longest run of digits and dots that holds an address, `255.255.255.255.`.
const MAX_RUN: usize = 16;

/// Anonymizes IPv4 addresses in a byte stream by masking their last octet, so `203.0.113.7`
/// becomes `203.0.113.x`.
///
/// An address is a run of digits and dots that splits into four decimal octets, with an optional
/// trailing dot that ends a sentence. A run can span chunks, so the redactor holds the run that a
/// chunk ends in until the next chunk or [`finish`](Self::finish) ends it.
#[derive(Debug, Default)]
pub struct Redactor {
    /// The run that the input ends in, while it is short enough to hold an address.
    run: Vec<u8>,
    /// Whether the current run is too long for an address, so its bytes pass through.
    long: bool,
    /// The addresses masked so far.
    masked: u64,
}

impl Redactor {
    /// Create a redactor at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the anonymized form of `input` to `out`.
    ///
    /// `out` lags `input` by the run that `input` ends in.
    pub fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            let len = input
                .iter()
                .position(|&byte| !is_run_byte(byte))
                .unwrap_or(input.len());

            self.extend_run(&input[..len], out);
            input = &input[len..];

            if input.is_empty() {
                break;
            }

            self.end_run(out);

            let len = input
                .iter()
                .position(|&byte| is_run_byte(byte))
                .unwrap_or(input.len());

            out.extend_from_slice(&input[..len]);
            input = &input[len..];
        }
    }

    /// End the stream, appending the run that it ends in to `out`.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.end_run(out);
    }

    /// The addresses masked so far.
    pub fn masked(&self) -> u64 {
        self.masked
    }

    /// Add `bytes` to the current run. A run too long for an address passes through.
    fn extend_run(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        if self.long {
            out.extend_from_slice(bytes);
            return;
        }

        self.run.extend_from_slice(bytes);

        if self.run.len() > MAX_RUN {
            out.append(&mut self.run);
            self.long = true;
        }
    }

    /// Append the current run to `out`, masked when it is an address, and start a new one.
    fn end_run(&mut self, out: &mut Vec<u8>) {
        self.long = false;

        match last_octet(&self.run) {
            Some(octet) => {
                out.extend_from_slice(&self.run[..octet.start]);
                out.push(b'x');
                out.extend_from_slice(&self.run[octet.end..]);
                self.masked += 1;
            }
            None => out.extend_from_slice(&self.run),
        }

        self.run.clear();
    }
}

/// Whether `byte` can be part of an address.
fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'.'
}

/// The range of the last octet when `run` is an address with an optional trailing dot.
fn last_octet(run: &[u8]) -> Option<Range<usize>> {
    let address = run.strip_suffix(b".").unwrap_or(run);
    let octets = address.split(|&byte| byte == b'.');

    if octets.clone().count() != 4 || !octets.clone().all(is_octet) {
        return None;
    }

    let start = address.iter().rposition(|&byte| byte == b'.')? + 1;
    Some(start..address.len())
}

/// Whether `digits` is a decimal octet, 0 to 255 in at most three digits.
fn is_octet(digits: &[u8]) -> bool {
    if !(1..=3).contains(&digits.len()) {
        return false;
    }

    let value = digits
        .iter()
        .fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));

    value <= 255
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Redact `input` in two chunks split at `at`, and return the output and the masked count.
    fn redact_split(input: &[u8], at: usize) -> (Vec<u8>, u64) {
        let mut redactor = Redactor::new();
        let mut out = Vec::new();

        redactor.push(&input[..at], &mut out);
        redactor.push(&input[at..], &mut out);
        redactor.finish(&mut out);

        (out, redactor.masked())
    }

    /// Redact `input` in one chunk.
    fn redact(input: &[u8]) -> (Vec<u8>, u64) {
        redact_split(input, 0)
    }

    #[test]
    fn masks_the_last_octet() {
        let (out, masked) = redact(br#"{"origin":"185.72.184.58"}"#);

        assert_eq!(out, br#"{"origin":"185.72.184.x"}"#);
        assert_eq!(masked, 1);
    }

    #[test]
    fn keeps_a_trailing_dot() {
        let (out, masked) = redact(b"from 10.0.0.255.");

        assert_eq!(out, b"from 10.0.0.x.");
        assert_eq!(masked, 1);
    }

    #[test]
    fn keeps_runs_that_are_not_addresses() {
        let input = b"v1.2.3 256.1.1.1 1.2.3.4.5 12345678.1.1.1 1..2.3 3.14 .";
        let (out, masked) = redact(input);

        assert_eq!(out, input);
        assert_eq!(masked, 0);
    }

    #[test]
    fn keeps_a_long_run_that_ends_in_an_address() {
        let input = b"12345678901234567.1.2.3";
        let (out, masked) = redact(input);

        assert_eq!(out, input);
        assert_eq!(masked, 0);
    }

    /// Every split gives the same output, so an address can span chunks.
    #[test]
    fn output_does_not_depend_on_chunk_boundaries() {
        let input = br#"{"origin":"203.0.113.7, 10.0.0.1"} 12345678901234567.1.2.3 192.168.1.1"#;
        let expected = br#"{"origin":"203.0.113.x, 10.0.0.x"} 12345678901234567.1.2.3 192.168.1.x"#;

        for at in 0..=input.len() {
            let (out, masked) = redact_split(input, at);

            assert_eq!(out, expected, "split at {at}");
            assert_eq!(masked, 3, "split at {at}");
        }
    }
}
