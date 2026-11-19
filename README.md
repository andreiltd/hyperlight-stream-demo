# hyperlight-stream-demo 

Stream an HTTP response body through a Hyperlight guest that anonymizes it.

The host fetches a page with hyper and passes the body to the guest as a stream and its trailers
as a future. The guest masks the last octet of every IPv4 address and streams the body back. It
returns trailers with its stats as a future.

```rust
#[guest_function("Handle")]
fn handle(
    body: StreamReader<u8>,
    trailers: FutureReader<Trailers>,
) -> Result<(StreamReader<u8>, FutureReader<Trailers>), HyperlightGuestError>
```

## Requirements

* Linux with KVM or mshv.
* `cargo install cargo-hyperlight --version 0.1.14`.
* `just`, and a nightly toolchain for `just fmt`.

## Usage

```console
$ just run http://httpbin.org/stream/3
2026-11-19T07:44:56.590467Z  INFO hl_http: sending request url=http://httpbin.org/stream/3
2026-11-19T07:44:56.807080Z  INFO hl_http: received response version=HTTP/1.1 status=200 OK
{"id":0,"args":{},"headers":{"Host":"httpbin.org","Te":"trailers"},"origin":"185.72.184.x",...}
{"id":1,"args":{},"headers":{"Host":"httpbin.org","Te":"trailers"},"origin":"185.72.184.x",...}
{"id":2,"args":{},"headers":{"Host":"httpbin.org","Te":"trailers"},"origin":"185.72.184.x",...}
2026-11-19T07:44:56.808854Z  INFO hl_http: trailer name="x-hyperlight-bytes-in" value="387"
2026-11-19T07:44:56.808896Z  INFO hl_http: trailer name="x-hyperlight-bytes-out" value="384"
2026-11-19T07:44:56.808906Z  INFO hl_http: trailer name="x-hyperlight-masked-ips" value="3"
```

Header and trailer fields are escaped in logs. The body is written unchanged to stdout after
redaction, so it can still contain terminal controls.

`http://httpbin.org/drip?duration=5&numbytes=5` shows bytes arriving one at a time.

## Layout

* `common`: the `Trailers` future value and the streaming `Redactor`, shared by host and guest.
* `guest`: the `Handle` guest function. It builds for the Hyperlight target, so it has its own
  workspace and toolchain.
* `host`: the `hl-http` binary, and the `get` and `filter` functions it uses.

## How it works

1. `get` sends the request. A task on a Tokio worker thread keeps reading the connection.
2. `filter` calls `Handle`. The guest spawns a task and returns its stream and future before any
   byte flows.
3. The main thread drives the sandbox with `block_on` while it uploads the body and downloads the
   guest's output concurrently.
4. The guest anonymizes each chunk as it arrives. An address split across chunks is held until
   it completes.
5. At the end of the body, the host resolves the trailers future with the upstream trailers. The
   guest appends its stats within the future size limit, closes its stream, and resolves its
   own future.

Trailer names must be nonempty HTTP tokens. Values reject ASCII controls except HTAB.
Each trailer future is limited to 16 KiB, including field separators and guest stats.
Non-UTF-8 upstream trailer bytes use replacement characters.

A failure aborts streams and futures rather than closing them. A broken upstream body aborts the
guest's input, the guest aborts its output, and `filter` returns the error. EOF on the guest's
output therefore means the body is complete. `Handle` itself does not fail, because errors
surface after it returns.
