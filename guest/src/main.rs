//! A Hyperlight guest that anonymizes an HTTP body as it streams through.
//!
//! The host calls `Handle` with a stream of the body and a future of its trailers. The guest
//! returns a stream of the anonymized body and a future of the trailers to send after it.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use hl_http_common::{Redactor, Trailers};
use hyperlight_guest::error::HyperlightGuestError;
use hyperlight_guest::future::{self, FutureReader};
use hyperlight_guest::stream::{self, StreamError, StreamReader, StreamWriter};
use hyperlight_guest_bin::guest_function;

/// Anonymize `body`, and return the result and the trailers to send after it.
///
/// The function returns before any byte flows. A guest task fills the returned stream, then
/// resolves the returned future with `trailers` and the filter's stats. A failure aborts both.
#[guest_function("Handle")]
fn handle(
    body: StreamReader<u8>,
    trailers: FutureReader<Trailers>,
) -> Result<(StreamReader<u8>, FutureReader<Trailers>), HyperlightGuestError> {
    let (output, writer) = stream::new();
    let trailers = future::produce(filter(body, trailers, writer));

    Ok((output, trailers))
}

/// Filter `body` into `output`, and return the trailers to send after it.
///
/// `output` closes once the trailers are ready and aborts on failure, so a reader that sees EOF
/// has the complete body.
async fn filter(
    body: StreamReader<u8>,
    trailers: FutureReader<Trailers>,
    mut output: StreamWriter<u8>,
) -> Result<Trailers, StreamError> {
    let result = anonymize(body, trailers, &mut output).await;

    match result {
        Ok(_) => output.close(),
        Err(_) => output.abort(),
    }

    result
}

/// Write the anonymized `body` to `output`, and return `trailers` with the filter's stats.
async fn anonymize(
    mut body: StreamReader<u8>,
    trailers: FutureReader<Trailers>,
    output: &mut StreamWriter<u8>,
) -> Result<Trailers, StreamError> {
    let mut redactor = Redactor::new();
    let mut bytes_in = 0;
    let mut bytes_out = 0;

    while let Some(chunk) = body.read_chunk().await? {
        let mut out = Vec::with_capacity(chunk.len());
        redactor.push(&chunk, &mut out);

        bytes_in += chunk.len();
        bytes_out += out.len();
        output.write_chunk(out.into()).await?;
    }

    let mut out = Vec::new();
    redactor.finish(&mut out);

    bytes_out += out.len();
    output.write_chunk(out.into()).await?;

    let mut trailers = trailers.await?;
    trailers.push("x-hyperlight-bytes-in", bytes_in.to_string())?;
    trailers.push("x-hyperlight-bytes-out", bytes_out.to_string())?;
    trailers.push("x-hyperlight-masked-ips", redactor.masked().to_string())?;

    Ok(trailers)
}
