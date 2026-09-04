# Known limitations

Deliberate trade-offs, confirmed real but assessed as not worth their fix
cost at the current stage — not oversights. Each entry says what the risk
actually is, why it wasn't closed, and what would close it if the
threat model changes. Distinct from `TODO`-style gaps: everything here was
evaluated and consciously left as is, most recently during the security
review following commit `be606e3`.

## Socket bind-then-chmod is not atomic

`ipc::bind_unix_socket` calls `UnixListener::bind` and then
`fs::set_permissions` as two separate syscalls. Between them, the socket
file briefly exists with the binding process's default (umask-derived)
permissions rather than `0600` — a real, if very short (two syscalls'
worth), window.

**Why not closed:** the two ways to close it fully both cost more than the
risk on this project's current single/few-user local threat model
justifies:

- wrap the bind in `umask(0077)` / restore — Rust's standard library
  doesn't expose `umask()`, so this needs the `libc` crate, a new
  dependency for a nanosecond-scale window;
- bind inside a directory that is itself `0700` (e.g. under
  `XDG_RUNTIME_DIR`, which this project already uses for scratch
  directories in `viper-helper.rs`) so the window is irrelevant — but this
  means changing every gateway's default socket path away from `/tmp/*.sock`,
  a disruptive change to every example config, script, and doc reference
  in this repository for a threat that isn't live right now.

**What would change this:** a genuinely multi-tenant or hostile-local-user
deployment target. At that point, the `XDG_RUNTIME_DIR`-based directory
approach is the right fix, not the `umask` one — it also closes the
umask-dependency risk `bind_unix_socket`'s `chmod` step already mitigates
after the fact, at the point of creation instead.

## No provider-endpoint host allowlist

A keyed model provider's `endpoint` must be `https://` (enforced,
`be606e3`), but any HTTPS host is otherwise accepted — a typo'd or
misconfigured `endpoint` sends the real API key to whatever host is
written there.

**Why not closed:** `endpoint` is administrator-owned configuration, not
Box- or agent-supplied input — `BACKEND_CONTRACT.md` already treats
administrator configuration as a trusted component, and a Box has no path
to influence this value at all. A hardcoded allowlist of "known" provider
hosts (`api.openai.com`, `api.anthropic.com`, `openrouter.ai`) would also
break legitimate configurations this project has never ruled out: an
Azure OpenAI-compatible endpoint, a self-hosted proxy, a regional mirror.
This is closer to a philosophical question about how much the config
format should second-guess its own administrator than an unambiguous gap.

**What would change this:** if a concrete need for one of those
alternative endpoint shapes never materializes and the operator population
is well-defined, an optional allowlist (opt-in, not mandatory) would be a
reasonable addition.

## Streaming: no active cancellation of an abandoned request

Documented in `STREAM_PLAN.md`'s "Implementation note" already, repeated
here for visibility: when a streaming call is abandoned because the
idle-chunk timeout trips, the background thread performing the blocking
HTTP request is not joined or cancelled. It keeps running, bounded only by
`max_stream_duration_seconds` (the client-level timeout), and its eventual
result is silently dropped.

**Why not closed:** `reqwest`'s blocking client exposes no
request-cancellation handle. Actively aborting an in-flight blocking HTTP
call would need lower-level socket control (or a move to the async client)
this design doesn't add.

**What would change this:** if the abandoned-thread accumulation under
load ever becomes measurable (many idle-timeouts in quick succession,
each holding a thread open for up to `max_stream_duration_seconds`), the
fix is a bounded thread pool with backpressure, or moving the streaming
transports onto `reqwest`'s async client with real cancellation — a bigger
change than this note's scope.
