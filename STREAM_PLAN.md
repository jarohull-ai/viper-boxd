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
line by line. Implemented first, for exactly that reason.

### OpenAI and OpenRouter — implemented

Both stream Chat Completions as Server-Sent Events: `data: {...}` lines,
terminated by a literal `data: [DONE]` line — verified against OpenAI's own
published streaming reference and OpenRouter's streaming docs before
writing any parser, not assumed from the non-streaming shape. One
`OpenAiCompatibleStreamTransport` serves both, mirroring the non-streaming
`OpenAiCompatibleTransport`. Two OpenRouter-specific things the parser
handles, confirmed from their docs:

- `:`-prefixed keep-alive comment lines (e.g. `: OPENROUTER PROCESSING`),
  skipped rather than fed to the JSON parser;
- a mid-stream failure arrives as a `data: {...}` event carrying a
  top-level `error` field instead of a `delta` — treated as a stream
  failure (`ERR_MODEL_FAILED`), not delivered as a delta.

`[stream]` for `openai`/`openrouter` requires `api_key_env`, same as their
non-streaming `MODEL_GENERATE` and `EMBED`.

### Anthropic — implemented

Anthropic's streaming uses typed SSE events (`event: <type>` paired with
`data: {...}`) rather than OpenAI's single implicit delta-per-event shape —
verified against Anthropic's own published streaming reference before
writing a parser, including their full worked example. The payload's own
`"type"` field always duplicates the `event:` line's type, so
`AnthropicStreamTransport` only reads `data:` lines and switches on that
field, without tracking `event:` separately — same overall shape as the
OpenAI-compatible parser. `message_stop` is the terminator (no `[DONE]`
sentinel); a `content_block_delta` only yields text when its own
`delta.type` is `text_delta` (tool-use/thinking delta types are skipped,
since a plain `MODEL_GENERATE` call never triggers them); `event: error` is
a distinct mid-stream failure event, not a field on some other event type.

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

### Implementation note: how the idle timeout is actually enforced

`reqwest`'s blocking client has no per-read timeout on a streaming response
body — its own `.timeout()` bounds the whole request. `OllamaStreamTransport`
runs the blocking HTTP call and line-by-line body read on a background
thread, sending each parsed line to the caller over an `mpsc::channel`; the
foreground loop uses `recv_timeout(idle_timeout_seconds)`, which is the real
idle-gap enforcement. The client's own `.timeout(max_stream_duration_seconds)`
is the absolute backstop underneath that, bounding the background thread
even if the foreground gives up early on an idle timeout. One accepted
limitation: on an idle-timeout return, the background thread is not joined
(a blocking `reqwest` request has no cancellation handle) — it keeps
running, bounded by the client timeout, and its eventual send to the
now-unreceived channel is silently dropped. This is a deliberate, documented
tradeoff, not an oversight: actively cancelling an in-flight blocking HTTP
request would need lower-level socket control this design doesn't add. See
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for what would change this
assessment.

## Verified end to end on this host

Real token-by-token streaming against `mistral:7b`: 16 `StreamChunk` frames
delivered over the wire in order, each with an incrementing `sequence`, the
final frame `done: true` with an empty `delta`, concatenating to the full
generated text. Confirmed the non-streaming path is provably unaffected
(same request against the same running gateway, without `stream: true`,
returns the ordinary single `Response`). Confirmed both documented failure
paths live: a streaming call missing `params.prompt` returns one `done:
true` chunk with `ERR_INVALID_REQUEST`; a streaming call against a gateway
with no `[stream]` table returns one `done: true` chunk with
`ERR_NOT_IMPLEMENTED`, both without ever contacting Ollama.

## Error codes

No new codes. Every code the final chunk's `error` field carries is one
already established elsewhere in the contract: `ERR_UNSUPPORTED_SCHEMA`,
`ERR_REQUEST_LIMIT_EXCEEDED`, `ERR_NOT_IMPLEMENTED`, `ERR_INVALID_REQUEST`
(all shared with the non-streaming path's setup checks), plus
`ERR_MODEL_PROMPT_INVALID`, `ERR_MODEL_FAILED`, and
`ERR_MODEL_RESPONSE_INVALID` for failures during or after the transport
call — carried in the final chunk's `error` field instead of a top-level
`Response.error`.

## Acceptance tests before this is considered done

- a non-streaming `MODEL_GENERATE` call is provably unaffected: same
  request/response shape, same tests, same behavior — **done**, verified
  both by the unchanged non-streaming test suite and live, side by side
  with a real streaming call against the same running gateway;
- `send_streaming_request` against a canned sequence of chunks delivers
  them in order and stops exactly at `done: true`, with no live provider
  or socket needed for that part — **done** (`ipc::tests`, using a real
  local `UnixListener` serving canned frames);
- a canned mid-stream failure surfaces as a single final chunk with `done:
  true` and the expected `error.code`, not a hang or a silent drop —
  **done** (`ipc::tests` and `model_provider::tests::streaming`);
- `max_requests` is consumed exactly once per streaming call, not once per
  chunk — **done**, by construction (checked once before the transport
  call, same as every other method);
- `cargo test --locked`, Clippy, and `cargo audit` all pass — **done**;
- verified against a real local Ollama instance on this host with
  `"stream": true`, not only canned chunks — **done**: real token-by-token
  deltas, both live failure paths (missing prompt, streaming not
  configured), and a live non-streaming regression check, all above;
- the idle-chunk timeout and max-stream-duration caps are both exercised
  and proven to terminate a stalled stream — **done**
  (`tests/model_stream_timeout.rs`, against deliberately slow/stuck raw TCP
  servers, since a live Ollama call responds too quickly to exercise this):
  a server that never sends a first chunk trips the idle timeout near 1s
  instead of waiting out a 5s hold; a server that stalls after one chunk
  trips it the same way, having already delivered that one delta; a server
  that stays alive but silent is still cut off by `max_stream_duration`
  even with a much longer idle timeout configured, confirming that cap is
  a real backstop and not merely config-validated.

## Verified: SSE parsing against real wire bytes

`tests/openai_compatible_stream.rs` runs `OpenAiCompatibleStreamTransport`
against deliberately crafted raw TCP servers sending realistic SSE bytes,
not high-level canned chunks — this is the layer where a subtly wrong
assumption about the wire format would hide. Covers: ordered in-order
delivery ending at a literal `data: [DONE]` line; OpenRouter's `:`-prefixed
keep-alive comments correctly skipped; a mid-stream `error` event failing
the call with no further deltas delivered; malformed JSON in a `data:`
line failing the call; a connection that closes before `[DONE]` failing
the call rather than silently succeeding.

`tests/anthropic_stream.rs` does the same for `AnthropicStreamTransport`,
using bytes taken directly from Anthropic's own "Full HTTP stream response"
documentation example (including the `ping` keep-alive event and the full
`message_start` → `content_block_delta` → `message_stop` sequence), plus
crafted cases for a mid-stream `event: error`, a non-`text_delta` content
block delta (tool use), and a connection closing before `message_stop`.

Not yet done for either: a live call against the real APIs with `stream:
true` (needs an operator-supplied key, same constraint as every other
live-key verification this session).

## Explicitly out of scope here

- streaming for `EMBED` (embeddings are not sequential — there is nothing
  to stream);
- streaming for `SEARCH` or `FETCH`;
- wiring streaming into `viper-gateway-probe` or a live Box demo (the
  non-streaming `--call MODEL_GENERATE` probe already proves the
  Box-to-gateway path; a streaming variant is a natural but separate
  follow-up once the transport itself is built and tested).
