//! Stream an HTTP response body through a Hyperlight guest that anonymizes it.
//!
//! [`get`] fetches a response with hyper. [`filter`] passes its body and trailers to the guest
//! as a stream and a future, and receives a stream and a future back.

use std::io::Write;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
pub use hl_http_common::Trailers;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Incoming};
use hyper::header::{CONNECTION, HOST, TE};
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use hyperlight_host::Sandbox;
use hyperlight_host::future::{self, FutureReader, FutureWriter};
use hyperlight_host::stream::{self, StreamReader, StreamWriter};
use tokio::net::TcpStream;

/// The release build of the guest in this repository.
pub const GUEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../guest/target/x86_64-hyperlight-none/release/hl-http-guest"
);

/// The guest function that filters a body.
const HANDLE: &str = "Handle";

/// Send a GET request for `url` over HTTP/1.1, and return the response once its head arrives.
///
/// The connection runs in a task on the current Tokio runtime, so the body streams in while
/// another thread reads it. Only `http` URLs are supported.
pub async fn get(url: &Uri) -> Result<Response<Incoming>> {
    if url.scheme_str() != Some("http") {
        bail!("only http URLs are supported: {url}");
    }

    let authority = url.authority().context("the URL has no host")?;
    let port = authority.port_u16().unwrap_or(80);

    let tcp = TcpStream::connect((authority.host(), port))
        .await
        .with_context(|| format!("failed to connect to {authority}"))?;

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;

    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!(%error, "connection failed");
        }
    });

    let path = url.path_and_query().map_or("/", |path| path.as_str());
    let request = Request::get(path)
        .header(HOST, authority.as_str())
        .header(TE, "trailers")
        .header(CONNECTION, "TE")
        .body(Empty::<Bytes>::new())?;

    Ok(sender.send_request(request).await?)
}

/// Stream `body` through the guest into `sink`, and return the trailers the guest sends after it.
///
/// The guest receives a stream of the body and a future of its trailers, and returns a stream and
/// a future. One drive of the sandbox moves both directions:
pub fn filter<B>(sandbox: &mut Sandbox, body: B, sink: &mut impl Write) -> Result<Trailers>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (body_reader, body_writer) = stream::new();
    let (trailers_reader, trailers_writer) = future::new();

    let (mut output, output_trailers): (StreamReader<u8>, FutureReader<Trailers>) =
        sandbox.call(HANDLE, (body_reader, trailers_reader))?;

    let upload = upload(body, body_writer, trailers_writer);

    let download = async {
        while let Some(chunk) = output.read_chunk().await? {
            sink.write_all(&chunk)?;
            sink.flush()?;
        }

        Ok(())
    };

    sandbox.block_on(async {
        tokio::try_join!(upload, download)?;
        Ok(output_trailers.await?)
    })
}

/// Write `body` to `writer` and its trailers to `trailers`.
///
/// A body error aborts both, so the guest sees a failure rather than a short body.
async fn upload<B>(
    body: B,
    mut writer: StreamWriter<u8>,
    trailers: FutureWriter<Trailers>,
) -> Result<()>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    match copy_body(body, &mut writer).await {
        Ok(fields) => {
            writer.close();
            trailers.write(fields)?;
            Ok(())
        }
        Err(error) => {
            writer.abort();
            Err(error)
        }
    }
}

/// Write the data frames of `body` to `writer` without copying, and return its trailers.
async fn copy_body<B>(mut body: B, writer: &mut StreamWriter<u8>) -> Result<Trailers>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut trailers = Trailers::default();

    while let Some(frame) = body.frame().await {
        let frame = match frame?.into_data() {
            Ok(data) => {
                writer.write_chunk(data).await?;
                continue;
            }
            Err(frame) => frame,
        };

        if let Ok(fields) = frame.into_trailers() {
            for (name, value) in &fields {
                trailers.push(name.as_str(), String::from_utf8_lossy(value.as_bytes()))?;
            }
        }
    }

    Ok(trailers)
}
