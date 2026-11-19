//! Stream local chunked responses through the guest.

use std::process::Command;
use std::time::Duration;

use hl_http::Trailers;
use hyper::Uri;
use hyperlight_host::future::{self, FutureReader, MAX_VALUE};
use hyperlight_host::stream::{self, StreamError, StreamReader};
use hyperlight_host::{Sandbox, SandboxBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

/// The body chunks. They split both addresses.
const CHUNKS: [&[u8]; 3] = [br#"{"origin":"203.0"#, br#".113.7"} 10.0.0"#, b".255.\n"];

/// The body with its addresses masked.
const EXPECTED: &[u8] = b"{\"origin\":\"203.0.113.x\"} 10.0.0.x.\n";

/// The last chunk and an `x-upstream` trailer.
const TRAILER: &[u8] = b"0\r\nx-upstream: done\r\n\r\n";

/// The guest anonymizes the body across chunk boundaries, and appends its stats to the upstream
/// trailers.
#[test]
fn filter_anonymizes_a_chunked_body_and_forwards_its_trailers() {
    let runtime = runtime();
    let url = serve(&runtime, &CHUNKS, TRAILER);
    let mut sandbox = sandbox();

    let response = runtime.block_on(hl_http::get(&url)).unwrap();
    let mut body = Vec::new();

    let trailers = hl_http::filter(&mut sandbox, response.into_body(), &mut body).unwrap();

    let bytes_in = CHUNKS.concat().len().to_string();
    let bytes_out = EXPECTED.len().to_string();
    let mut expected = Trailers::default();
    expected.push("x-upstream", "done").unwrap();
    expected.push("x-hyperlight-bytes-in", bytes_in).unwrap();
    expected.push("x-hyperlight-bytes-out", bytes_out).unwrap();
    expected.push("x-hyperlight-masked-ips", "2").unwrap();

    assert_eq!(
        String::from_utf8_lossy(&body),
        String::from_utf8_lossy(EXPECTED)
    );
    assert_eq!(trailers, expected);
}

/// A body that breaks fails the filter, and the sandbox filters the next body.
#[test]
fn filter_fails_when_the_upstream_body_breaks() {
    let runtime = runtime();
    let broken = serve(&runtime, &CHUNKS[..1], b"");
    let complete = serve(&runtime, &CHUNKS, TRAILER);
    let mut sandbox = sandbox();

    let response = runtime.block_on(hl_http::get(&broken)).unwrap();
    let mut body = Vec::new();

    let error = hl_http::filter(&mut sandbox, response.into_body(), &mut body).unwrap_err();

    assert!(error.downcast_ref::<hyper::Error>().is_some(), "{error:?}");
    assert!(EXPECTED.starts_with(&body));
    assert!(sandbox.status().is_ready());

    let response = runtime.block_on(hl_http::get(&complete)).unwrap();
    let mut body = Vec::new();

    hl_http::filter(&mut sandbox, response.into_body(), &mut body).unwrap();

    assert_eq!(body, EXPECTED);
}

/// Stats that exceed the future limit must fail the body, not leave a clean EOF.
#[test]
fn guest_aborts_both_outputs_when_stats_exceed_the_trailer_limit() {
    let mut sandbox = sandbox();
    let (body, mut writer) = stream::new();
    let (trailers, trailers_writer) = future::new();
    let mut fields = Trailers::default();
    fields
        .push("x-upstream", "a".repeat(MAX_VALUE - "x-upstream".len() - 4))
        .unwrap();

    let (mut output, output_trailers): (StreamReader<u8>, FutureReader<Trailers>) =
        sandbox.call("Handle", (body, trailers)).unwrap();

    let (body_result, trailers_result) = sandbox
        .block_on(async {
            writer.write_all(b"demo\n").await?;
            writer.close();
            trailers_writer.write(fields)?;

            let body_result = async {
                while output.read_chunk().await?.is_some() {}

                Ok::<_, StreamError>(())
            }
            .await;
            let trailers_result = output_trailers.await;

            Ok::<_, anyhow::Error>((body_result, trailers_result))
        })
        .unwrap();

    assert_eq!(body_result, Err(StreamError::Aborted));
    assert_eq!(trailers_result, Err(StreamError::Aborted));
    assert!(sandbox.status().is_ready());
}

/// HTTP obs-text can encode Unicode controls, which must stay escaped in logs.
#[test]
fn cli_escapes_header_and_trailer_fields() {
    let runtime = runtime();
    let url = serve(
        &runtime,
        &CHUNKS,
        b"0\r\nx-upstream: visible\xc2\x85forged\r\n\r\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_hl-http"))
        .arg(url.to_string())
        .env("HL_HTTP_GUEST", hl_http::GUEST)
        .env("RUST_LOG", "hl_http=debug")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success(), "{stderr}");
    assert_eq!(output.stdout, EXPECTED);
    assert!(!stderr.contains('\u{85}'), "{stderr}");
    assert!(
        stderr.contains(r#"name="x-upstream" value="visible\u{85}forged""#),
        "{stderr}"
    );
    assert!(
        stderr.contains(r#"name="transfer-encoding" value="chunked""#),
        "{stderr}"
    );
}

/// A runtime whose worker thread runs the server and the HTTP connection.
fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap()
}

/// A sandbox running the release build of the guest.
fn sandbox() -> Sandbox {
    SandboxBuilder::from_file(hl_http::GUEST).build().unwrap()
}

/// Serve one request on `runtime`, and return its URL.
///
/// The response sends `chunks` as a chunked body, then `end` and closes the connection. A pause
/// after each chunk makes it likely to arrive as its own frame.
fn serve(runtime: &Runtime, chunks: &'static [&'static [u8]], end: &'static [u8]) -> Uri {
    let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());

    runtime.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();

        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }

        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-upstream\r\n\r\n",
            )
            .await
            .unwrap();

        for chunk in chunks {
            let head = format!("{:x}\r\n", chunk.len());

            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(chunk).await.unwrap();
            socket.write_all(b"\r\n").await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        socket.write_all(end).await.unwrap();
    });

    url.parse().unwrap()
}
