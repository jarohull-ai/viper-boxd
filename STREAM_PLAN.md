# Streaming MODEL_GENERATE — implementation contract

## Why this exists, and why it's a decision, not an addition

`viper_boxd::ipc` is strictly one request, one response, per connection:
`send_request` writes one `Request` line, then `read_line`s exactly once and
returns. Every gateway's `serve()` mirrors this — read one line, write one
line, close. Real token-by-token model output needs many frames per logical
request. That is a change to how the transport is *used*, not a new wire
format: JSON-lines already supports arbitrarily many lines per connection,
today's code just never keeps the connection open long enough to send more
than one.

## Decision: STREAM is not a fifth gateway method

Every real provider (Ollama, OpenAI, Anthropic, OpenRouter) models streaming
as a flag on the same generate/completions call, not a separate endpoint.
This plan does the same: `MODEL_GENERATE` gains an optional
`params.stream: true`. There is no `STREAM` method name anywhere in
`GATEWAY_CONTRACT.md` or the IPC contract.

## Wire format

A non-streaming call is completely unchanged: one `Request` in, one
`Response` out, connection closes. `Response` and `send_request` are not
touched by this plan at all — every existing caller (`SEARCH`, `FETCH`,
`EMBED`, non-streaming `MODEL_GENERATE`) keeps working with zero code or
behavior change.

A streaming call keeps the connection open and sends a sequence of a new
message type instead of one `Response`:

```json
{"version":"1.0","request_id":"...","audit_trace_id":"...","sequence":0,"delta":"Hello","done":false}
{"version":"1.0","request_id":"...","audit_trace_id":"...","sequence":1,"delta":" world","done":false}
{"version":"1.0","request_id":"...","audit_trace_id":"...","sequence":2,"delta":"","done":true}
```

`done: true` marks the last frame; no more will follow and the connection
closes after it. A stream that fails partway still ends with exactly one
`done: true` frame, carrying `error` instead of a further `delta`:

```json
{"version":"1.0","request_id":"...","audit_trace_id":"...","sequence":2,"delta":"","done":true,"error":{"code":"ERR_MODEL_FAILED","message":"..."}}
```

Every frame carries its own `audit_trace_id` — generated once per frame via
the existing `ipc::generate_audit_trace_id`, matching the invariant that
every response on the wire is independently traceable, same as today.

## Client API

Purely additive to `ipc.rs`:

```rust
pub struct StreamChunk {
    pub version: String,
    pub request_id: String,
    pub audit_trace_id: String,
    pub sequence: u64,
    pub delta: String,
    pub done: bool,
    pub error: Option<IpcErrorBody>,
}

pub fn send_streaming_request(
    socket_path: &str,
    request: &Request,
    on_chunk: impl FnMut(&StreamChunk),
) -> Result<(), ClientError>;
```

It writes the request line exactly like `send_request`, then loops
`read_line`, parsing and dispatching each `StreamChunk` to the callback
until `done` or the connection closes. `send_request` and `Response` are
unmodified; this is a new function, not a replacement.

## Server-side

`viper-model-gateway`'s `serve()` inspects the parsed `Request` before
dispatch: `method == "MODEL_GENERATE" && params.stream == true` branches
into a streaming handler that writes a sequence of `StreamChunk` lines
instead of calling today's `handle()` path, which stays completely
unchanged for every other case. A `ModelStreamTransport` trait (mirroring
`ModelTransport`) delivers chunks incrementally instead of one `Vec<u8>`
blob, isolating parsing so it stays unit-testable with a canned sequence of
chunks, no live provider needed.

## Provider staging — Ollama first, on purpose

Ollama's own `/api/generate` with `"stream": true` returns a response body
that is itself newline-delimited JSON — symmetric with our own wire format,
and readable incrementally off `reqwest::blocking::Response`'s `Read` impl
line by line. This is the first and only provider implemented here.

OpenAI, Anthropic, and OpenRouter stream via Server-Sent Events
(`text/event-stream`, `data: {...}` frames, each with its own per-provider
event shape — OpenAI-compatible ends in `data: [DONE]`, Anthropic has typed
events like `content_block_delta`/`message_stop`). Real, doable, but a
distinct parser per shape and meaningfully more work than Ollama's case.
Explicitly out of scope for this round, so it isn't guessed or half-built.

## Policy changes streaming requires

A streaming connection is a new resource-exhaustion surface the one-shot
model didn't have: a stuck backend or a client that never reads can hold a
gateway connection open indefinitely. Two new limits, both fixed by
operator config, never caller-supplied:

- **idle-chunk timeout** replaces the whole-call `timeout_seconds` for a
  streaming call: the limit applies to the gap between chunks, not the
  total stream duration, so a legitimately long generation isn't killed
  early just because a bounded whole-call timeout doesn't fit token
  streaming;
- **max stream duration**, an absolute cap regardless of chunk activity, so
  a technically-alive-but-glacial stream can't hold a connection forever.

`max_requests` budget accounting is unchanged: one streaming call consumes
one unit of the shared budget, same as one non-streaming call, checked
before the first chunk is requested from the provider — not once per chunk.

## Error codes

No new codes. `ERR_MODEL_PROMPT_INVALID`, `ERR_MODEL_FAILED`, and
`ERR_MODEL_RESPONSE_INVALID` are reused, carried in the final chunk's
`error` field instead of a top-level `Response.error`.

## Acceptance tests before this is considered done

- a non-streaming `MODEL_GENERATE` call is provably unaffected: same
  request/response shape, same tests, same behavior, whether or not this
  plan is implemented;
- `send_streaming_request` against a canned sequence of chunks delivers
  them in order and stops exactly at `done: true`, with no live provider
  or socket needed for that part;
- a canned mid-stream failure surfaces as a single final chunk with `done:
  true` and the expected `error.code`, not a hang or a silent drop;
- the idle-chunk timeout and max-stream-duration caps are both exercised
  and proven to terminate a stalled stream;
- `max_requests` is consumed exactly once per streaming call, not once per
  chunk;
- `cargo test --locked`, Clippy, and `cargo audit` all pass;
- verified against a real local Ollama instance on this host with
  `"stream": true`, not only canned chunks.

## Explicitly out of scope here

- OpenAI, Anthropic, and OpenRouter streaming (SSE parsing per provider);
- streaming for `EMBED` (embeddings are not sequential — there is nothing
  to stream);
- streaming for `SEARCH` or `FETCH`;
- wiring streaming into `viper-gateway-probe` or a live Box demo (the
  non-streaming `--call MODEL_GENERATE` probe already proves the
  Box-to-gateway path; a streaming variant is a natural but separate
  follow-up once the transport itself is built and tested).
