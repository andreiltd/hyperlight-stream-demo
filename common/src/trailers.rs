//! HTTP trailer fields that futures carry across the sandbox boundary.

use alloc::string::String;
use alloc::vec::Vec;

use bytes::Bytes;
use hyperlight_common::future::{FutureValue, MAX_VALUE};
use hyperlight_common::stream::StreamError;

/// HTTP trailer fields, in order.
///
/// A future carries them as `name: value` lines that end in CRLF, the HTTP/1.1 field syntax.
/// Names are nonempty HTTP tokens. Values contain no ASCII controls except HTAB.
/// The encoding fits within [`MAX_VALUE`], including field separators.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trailers(Vec<(String, String)>);

impl Trailers {
    /// Append a field, rejecting invalid fields or an encoding over [`MAX_VALUE`].
    ///
    /// An error leaves the existing fields unchanged.
    pub fn push(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), StreamError> {
        let name = name.into();
        let value = value.into();

        if !valid_field(&name, &value) {
            return Err(StreamError::InvalidValue);
        }

        let used: usize = self
            .0
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum();
        let added = name.len().saturating_add(value.len()).saturating_add(4);

        if added > MAX_VALUE - used {
            return Err(StreamError::ValueTooLarge);
        }

        self.0.push((name, value));
        Ok(())
    }

    /// The fields, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

impl FutureValue for Trailers {
    fn encode(self) -> Bytes {
        let mut text = String::new();

        for (name, value) in self.0 {
            text.push_str(&name);
            text.push_str(": ");
            text.push_str(&value);
            text.push_str("\r\n");
        }

        Bytes::from(text)
    }

    fn decode(bytes: Bytes) -> Option<Self> {
        if bytes.len() > MAX_VALUE {
            return None;
        }

        let text = core::str::from_utf8(&bytes).ok()?;

        text.split_inclusive("\r\n")
            .map(|line| {
                let (name, value) = line.strip_suffix("\r\n")?.split_once(": ")?;
                valid_field(name, value).then(|| (name.into(), value.into()))
            })
            .collect::<Option<_>>()
            .map(Self)
    }
}

/// Check HTTP token names and field-value bytes before construction or decoding.
fn valid_field(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn fields_round_trip_in_order() {
        let mut trailers = Trailers::default();
        trailers.push("x-one", "1").unwrap();
        trailers.push("x-two", "a: b").unwrap();

        let bytes = trailers.clone().encode();

        assert_eq!(bytes, "x-one: 1\r\nx-two: a: b\r\n");
        assert_eq!(Trailers::decode(bytes), Some(trailers));
    }

    #[test]
    fn no_fields_encode_to_no_bytes() {
        let bytes = Trailers::default().encode();

        assert!(bytes.is_empty());
        assert_eq!(Trailers::decode(bytes), Some(Trailers::default()));
    }

    #[test]
    fn a_line_without_crlf_is_invalid() {
        assert_eq!(Trailers::decode(Bytes::from_static(b"x-one: 1")), None);
    }

    /// Empty field names are invalid on either side of the guest boundary.
    #[test]
    fn empty_name_is_rejected() {
        assert_eq!(
            Trailers::default().push("", "value"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(Trailers::decode(Bytes::from_static(b": value\r\n")), None);
    }

    /// Whitespace is not part of an HTTP token.
    #[test]
    fn name_with_space_is_rejected() {
        assert_eq!(
            Trailers::default().push("bad name", "value"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(
            Trailers::decode(Bytes::from_static(b"bad name: value\r\n")),
            None
        );
    }

    /// A value must not manufacture another field during encoding.
    #[test]
    fn crlf_injection_is_rejected() {
        let mut trailers = Trailers::default();

        assert_eq!(
            trailers.push("x-one", "ok\r\nx-forged: yes"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(trailers, Trailers::default());
    }

    /// Bare CR must not survive untrusted decoding.
    #[test]
    fn carriage_return_is_rejected() {
        assert_eq!(
            Trailers::default().push("x", "a\rb"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(Trailers::decode(Bytes::from_static(b"x: a\rb\r\n")), None);
    }

    /// Bare LF must not survive untrusted decoding.
    #[test]
    fn line_feed_is_rejected() {
        assert_eq!(
            Trailers::default().push("x", "a\nb"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(Trailers::decode(Bytes::from_static(b"x: a\nb\r\n")), None);
    }

    /// NUL is invalid even though it does not split a CRLF-delimited field.
    #[test]
    fn nul_is_rejected() {
        assert_eq!(
            Trailers::default().push("x", "a\0b"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(Trailers::decode(Bytes::from_static(b"x: a\0b\r\n")), None);
    }

    /// Terminal escape sequences cannot enter a trailer value.
    #[test]
    fn escape_is_rejected() {
        assert_eq!(
            Trailers::default().push("x", "\x1b[2J"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(
            Trailers::decode(Bytes::from_static(b"x: \x1b[2J\r\n")),
            None
        );
    }

    /// DEL is outside the visible ASCII range.
    #[test]
    fn del_is_rejected() {
        assert_eq!(
            Trailers::default().push("x", "a\x7fb"),
            Err(StreamError::InvalidValue)
        );
        assert_eq!(Trailers::decode(Bytes::from_static(b"x: a\x7fb\r\n")), None);
    }

    /// Token punctuation, HTAB and UTF-8 field bytes retain their values.
    #[test]
    fn allowed_field_bytes_round_trip() {
        let mut trailers = Trailers::default();
        trailers
            .push("!#$%&'*+-.^_`|~AZaz09", "a\t\u{85}b")
            .unwrap();
        trailers.push("x-empty", "").unwrap();

        assert_eq!(Trailers::decode(trailers.clone().encode()), Some(trailers));
    }

    /// The future limit includes the name, colon, space and CRLF.
    #[test]
    fn exact_future_limit_round_trips() {
        let mut trailers = Trailers::default();
        trailers.push("x", "a".repeat(MAX_VALUE - 5)).unwrap();
        let bytes = trailers.clone().encode();

        assert_eq!(bytes.len(), MAX_VALUE);
        assert_eq!(Trailers::decode(bytes), Some(trailers));
    }

    /// Construction and decoding enforce the same byte limit.
    #[test]
    fn field_over_future_limit_is_rejected() {
        let value = "a".repeat(MAX_VALUE - 4);

        assert_eq!(
            Trailers::default().push("x", &value),
            Err(StreamError::ValueTooLarge)
        );
        assert_eq!(
            Trailers::decode(Bytes::from(format!("x: {value}\r\n"))),
            None
        );
    }

    /// Appending stats must account for fields already in the future.
    #[test]
    fn oversized_append_preserves_existing_fields() {
        let mut trailers = Trailers::default();
        trailers.push("x", "a".repeat(MAX_VALUE - 5)).unwrap();
        let original = trailers.clone();

        assert_eq!(
            trailers.push("x-hyperlight-bytes-in", "5"),
            Err(StreamError::ValueTooLarge)
        );
        assert_eq!(trailers, original);
    }
}
