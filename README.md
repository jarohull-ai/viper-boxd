# viper-boxd

**Trusted execution daemon for JFP Box policies — simulator phase**

> **Alpha. Not for production. No independent security review has been
> performed.** This is an unprivileged simulator and a set of trusted-daemon
> prototypes (`viper-helper`, the research and model gateways); it is not an
> audited sandbox or runtime. Every isolation and gateway-security claim in
> this repository is backed by automated tests and, where noted, manual live
> verification on one development host — not by third-party review.
> `BACKEND_DECISION.md` and `KNOWN_LIMITATIONS.md` list what is deliberately
> not yet done, including the independent security review required before
> any real agent execution. Feedback, issues, and bug reports are welcome
> via GitHub Issues; see [Contact](#contact) for direct contact.

## Status

- **Project:** `viper-boxd`
- **Version:** `0.1.0-alpha.1`
- **Stability:** alpha / experimental
- **Execution scope:** controlled systemd test runner only; no arbitrary agent
  command execution
- **Security status:** automated boundary probes and local verification only;
  no independent audit
- **Repository visibility:** private during alpha development

## Purpose

JFP Box validates whether an agent task manifest is internally consistent. It
does not create namespaces, mount filesystems, enforce network policy, or start
agents. `viper-boxd` is the planned trusted daemon that will enforce an
accepted policy at runtime.

```text
Agent / UI
    │  workspace_id, profile_id, task_id
    ▼
JFP Box validator ── PLAN_ACCEPTED / PLAN_REJECTED
    │
    ▼
viper-boxd (trusted control boundary)
    ├── filesystem and process isolation
    ├── resource and lifecycle limits
    ├── gateway mediation
    ├── output validation / patch handoff
    └── audit records
```

For teams operating AI-enabled systems in regulated settings, these runtime
controls and audit records can support technical evidence of how a task was
constrained and handled. viper-boxd is not a compliance product, legal
assessment, or certification; applicable obligations depend on the system's
intended use and the organization deploying it.

## Non-goals for the design phase

- no agent execution;
- no direct handling of model or provider API keys;
- no arbitrary host-path or sandbox-flag input from agents;
- no claim of kernel-level security until an implementation is independently
  reviewed and tested.

## Relationship to other projects

`viper-boxd` is the runtime-enforcement layer in the JFP ecosystem.

- `jfp-box` is the mandatory policy gate. `viper-boxd` must treat
  `PLAN_ACCEPTED` as necessary but not sufficient for safe execution.
- `viper-boxd` owns the trusted mapping from logical `workspace_id`,
  `profile_id`, gateway references, and resource limits to host configuration.
  Agents never provide host paths, capabilities, ports, or backend arguments.
- `jfp-box-agent` is an ACP-facing adapter that calls JFP Box first and then
  calls `viper-boxd` only for accepted plans. AionUi or another ACP client sees
  the adapter; `viper-boxd` remains an internal runtime/backend component.

This repository is not a replacement for `jfp-box`: it depends on the validator
contract and focuses on enforcement, lifecycle control, gateway mediation,
lineage, admission control, metrics, and audit output.

## Simulator quick start

```bash
cargo run -- plan \
  --manifest examples/research.jfp \
  --profile examples/research-profile.toml \
  --workspace-id WORKSPACE_A
```

The command validates the manifest through `jfp-box`, compares it with the
trusted TOML profile, and prints a JSON isolation plan. It performs no mounts,
namespace changes, network operations, process spawns, or workspace writes.

Exit codes are `0` for `PLAN_ACCEPTED`, `1` for a rejected plan, and `2` for
CLI, file, or profile errors.

## Capability probe

The read-only capability probe reports kernel and tool presence without
creating namespaces, mounts, cgroups, processes, or network connections:

```bash
cargo run -- capabilities
```

The result deliberately reports `backend_ready: false` and
`enforceable: false`. Presence is not proof that a future privileged backend
can enforce an isolation control; that requires backend-specific verification.

## No-op backend self-test

The contract lifecycle can be exercised through the unprivileged mock helper.
In one terminal start the Unix-socket server:

```bash
cargo run --bin viper-helper-mock -- /tmp/viper-helper-mock.sock
```

Then run the viper-boxd IPC client in another:

```bash
cargo run --bin viper-boxd -- backend-self-test --socket /tmp/viper-helper-mock.sock
```

The experimental systemd helper is a separate binary and is not used by the
mock self-test:

```bash
cargo run --bin viper-helper -- /tmp/viper-helper.sock
```

It accepts only the fixed test executable `/usr/bin/sleep 10`; it does not
accept arbitrary commands, paths, or systemd properties.

The mock helper tests `SPAWN`, `STATUS`, `KILL`, and `CLEANUP` over a
versioned JSON-lines Unix socket. It first exposes the real read-only capability
probe and refuses `spawn` when a requested capability is not enforceable. It
does not create an isolated child, namespace, mount, cgroup, or network
connection.

### Filesystem isolation probe

The real helper also exposes a deliberately narrow probe for the filesystem
policy. It runs the checked-in `viper-fs-probe` binary in a transient systemd
unit, permits writes only to a helper-created runtime scratch directory, and
checks that a protected host path cannot be written:

```bash
cargo build --bins
cargo run --bin viper-helper -- /tmp/viper-helper.sock
cargo run -- filesystem-probe --socket /tmp/viper-helper.sock
```

The expected result contains `scratch_write: true` and
`outside_write_denied: true`. This command has intentional side effects: it
creates and removes one temporary runtime directory and transient systemd
unit. It is a verification probe, not a general command runner. A successful
probe demonstrates this tested policy on the current host; it is not a claim
that the future privileged runner is complete or independently audited.

### Network-deny probe

The helper enforces `network_mode: DENY` for its current systemd test unit by
setting `PrivateNetwork=yes`. The fixed network probe verifies both an external
address and a loopback address, without accepting a URL or command from the
caller:

```bash
cargo build --bins
cargo run --bin viper-helper -- /tmp/viper-helper.sock
cargo run -- network-probe --socket /tmp/viper-helper.sock
```

The expected result contains `external_network_blocked: true` and
`local_network_blocked: true`. Any `network_mode` other than `DENY` or
`GATEWAY_ONLY` is rejected fail-closed.

### Signal isolation probe

The helper applies a deny-list `SystemCallFilter=` for the Linux signal
delivery syscalls (`kill`, `tkill`, `tgkill`, queued-signal and pidfd forms).
The signal probe runs `viper-signal-probe` in a transient unit and attempts
`kill -0` (a permission check only, no signal is delivered) against its own
PID and the helper's PID:

```bash
cargo build --bins
cargo run --bin viper-helper -- /tmp/viper-helper.sock
cargo run -- signal-probe --socket /tmp/viper-helper.sock
```

The expected result contains `self_signal_denied: true` and
`target_signal_denied: true`. Lifecycle remains available through systemd's
cgroup stop operation; a Box cannot use host signal syscalls. This command has
intentional side effects: it creates one transient systemd unit. Either false
value is a real leak, not a probe defect.

### Resource limit probe

The helper sets `CPUQuota=` and `MemoryMax=` on every spawned unit, but
neither is exercised by the other probes. The resource probe runs
`viper-resource-probe` in a transient unit with fixed test limits
(`CPUQuota=20%`, `MemoryMax=64MiB`) and checks that both are actually
enforced by the kernel, not just configured: a CPU-bound busy loop's
CPU-time/wall-time ratio (read from `/proc/self/stat`) must stay well
below 1.0, and a disposable child process that tries to allocate and
touch memory well past the limit must be killed by the kernel (or aborted
by the allocator) before it finishes - a fixed, bounded attempt, not an
open-ended one:

```bash
cargo build --bins
cargo run --bin viper-helper -- /tmp/viper-helper.sock
cargo run -- resource-probe --socket /tmp/viper-helper.sock
```

The expected result contains `cpu_quota_enforced: true` and
`memory_limit_enforced: true`. The memory check's child runs in the same
cgroup as its parent. It writes every requested page and reports both its RSS
and touched-page count; enforcement is proven either by an OOM signal or by a
resident set capped at the configured limit after all pages were touched.
This handles supported kernels that cap the child without propagating an OOM
signal to its parent.

### Phase-2 runtime state and observability

`viper-boxd::lineage` persists versioned parent/child policy snapshots as
atomic owner-only JSON files. The intended service directory is
`/var/lib/viper-boxd/lineage`; tests must use an explicit temporary directory.
Corrupt records, unknown parents and policy broadening fail closed on reload.

`viper-boxd::admission` has a default global capacity of 50 active Boxes and
a FIFO queue. `VIPER_MAX_ACTIVE_BOXES` configures the helper limit. Helper IPC
exposes `admission/status` and `admission/drain`. A successful `kill` or TTL
expiry frees one slot and drains FIFO work; queued requests can be cancelled by
`kill` or `cleanup` before they start.

`viper-boxd::observability` emits JSONL records suitable for Filebeat and
formats Prometheus text metrics (`viper_boxes_active`, queue, CPU/RAM limits
and model-cost counter). The administrator-facing Filebeat input template is
[`deploy/filebeat-viper-boxd.yml`](deploy/filebeat-viper-boxd.yml). It contains
no Elasticsearch URL or credentials; those remain administrator configuration.
Set `VIPER_AUDIT_LOG=/var/log/viper-boxd/audit.jsonl` for helper IPC audit
events, then request helper method `metrics` to obtain the Prometheus text
payload. Filebeat and Elasticsearch are deployment dependencies, not embedded
in the helper.

### Phase-3 recovery, CI and time audit

On startup, `viper-helper` opens the lineage store
(`/var/lib/viper-boxd/lineage` by default, or `VIPER_LINEAGE_DIR`) before
binding its IPC socket. If the directory exists, the helper scans active
`viper-box-*.service` user units through systemd. A unit with no matching
lineage record is treated as an orphan: the helper stops it, resets failed
state, removes its deterministic runtime scratch directory, and emits an
`orphan_box_reconciled` JSONL audit event when `VIPER_AUDIT_LOG` is set. If
any part of that kill/cleanup sequence fails, helper startup fails closed.

Audit JSONL entries now include both UTC wall-clock time and operation
duration:

```json
{"schema":"viper-boxd.audit.v0","timestamp":"2026-09-05T16:59:23Z","timestamp_unix_ms":1788627563191,"duration_ms":7,"event":"helper_ipc","fields":{}}
```

`timestamp` is formatted as UTC independent of the local timezone.
`duration_ms` is measured from a monotonic timer around the helper operation.
Time synchronization remains a host deployment requirement; the helper reports
UTC timestamps but does not configure NTP itself. Operators should verify the
host with `timedatectl`/chrony/ntpd and alert on unsynchronized clocks.

The GitHub Actions workflow
`.github/workflows/phase3-security.yml` runs on every push and pull request.
It builds all binaries, requires a usable systemd user manager, runs the real
filesystem, network, signal and resource escape probes, and checks that audit
logs contain UTC `timestamp` and numeric `duration_ms` fields.

Before running the real probes, CI performs a canary check for
`ProtectHome=read-only` enforcement in a `systemd --user` unit. If the runner
has a user manager but cannot enforce user-unit mount namespacing, the workflow
emits a warning and skips the real escape probes on that host. Treat that as an
environment limitation, not as boundary coverage. Release-gating Phase 3 should
use a host or self-hosted runner where this canary fails closed and the probes
actually execute. The same workflow also runs daily and on manual dispatch; in
those modes it additionally runs the ignored DoS regression tests in
`tests/dos_heavy.rs`, including the 100 MiB IPC framing check and 1000-way
admission stress test.

The fast regression suite also includes `tests/adversarial_inputs.rs`, covering
overlong paths, control characters in manifests, repetitive malformed
manifests, missing files, unreadable/corrupt TOML profiles, premature gateway
disconnects and malformed gateway response types.

### Gateway-only networking

A Box may be granted access to one or more running gateways without ever
receiving a raw socket path or real network access. The helper resolves a
`gateway_ref` against an administrator-owned registry file (never against a
caller-supplied path) and bind-mounts only that gateway's socket into the
unit with `BindPaths=`. `PrivateNetwork=yes` stays set regardless: a Unix
socket bind grants no IP networking, so direct network access remains fully
denied. See [BACKEND_DECISION.md](BACKEND_DECISION.md) ("gateway references,
not sockets/URLs") for the reasoning.

```bash
cargo build --bins
cargo run --bin viper-gateway-mock -- /tmp/viper-gateway-mock.sock
cargo run --bin viper-helper -- /tmp/viper-helper.sock examples/gateway-registry.toml
cargo run --bin viper-boxd -- gateway-probe \
  --socket /tmp/viper-helper.sock --gateway-ref MOCK_RESEARCH_V0
```

The probe runs `viper-gateway-probe` in a transient systemd unit whose only
network path is the bind-mounted gateway socket. The expected result contains
`gateway_reachable: true`, `gateway_denies_unknown_method: true` (proving
default-deny holds even for an unsupported method), and the same
`external_network_blocked: true` / `local_network_blocked: true` as the
network-deny probe. A `spawn` request may request the same wiring for a real
Box lifecycle with `"network_mode": "GATEWAY_ONLY", "gateway_refs": [...]`;
an unknown or unreachable reference fails closed with `ERR_NETWORK_SETUP`.

Add `--call MODEL_GENERATE` to prove a real functional round trip, not just
reachability — a fixed, built-in prompt, never a caller-supplied one:

```bash
cargo run --bin viper-model-gateway -- /tmp/viper-model-gateway.sock \
  examples/model-gateway.toml
cargo run --bin viper-boxd -- gateway-probe --socket /tmp/viper-helper.sock \
  --gateway-ref VIPER_LOCAL_OLLAMA_V1 --call MODEL_GENERATE
```

This is the full loop closed end to end: a Box spawned with
`network_mode: GATEWAY_ONLY` and `gateway_refs: [VIPER_LOCAL_OLLAMA_V1]`
reaches only its bind-mounted gateway socket, calls a real `MODEL_GENERATE`
through it, and gets back a real answer from Ollama — while direct network
access stays fully denied. Verified together on this host: `spawn` a Box
under that exact policy (confirmed `status: active`), run the probe above
against the same gateway while the Box is alive, then `kill`/`cleanup` it.
`spawn`'s payload deliberately stays the fixed `/usr/bin/sleep` test
executable per `BACKEND_CONTRACT.md` ("arbitrary shell commands are not
supported"); the probe runs as a second unit under byte-identical isolation
properties rather than adding a way to run arbitrary code inside a spawned
Box.

### Mock gateway contract

The gateway boundary is specified in [GATEWAY_CONTRACT.md](GATEWAY_CONTRACT.md)
and can be exercised without network access:

```bash
cargo run --bin viper-gateway-mock -- /tmp/viper-gateway-mock.sock
cargo run -- gateway-self-test --socket /tmp/viper-gateway-mock.sock
```

The mock supports only `SEARCH`, `FETCH`, and `MODEL_GENERATE`, returns fixed
responses, labels research data as `UNTRUSTED_EVIDENCE`, and rejects unknown
tools. It never opens an outbound connection and is not a production gateway.
The staged live-fetch policy is documented in
[RESEARCH_GATEWAY_PLAN.md](RESEARCH_GATEWAY_PLAN.md); no external transport is
enabled yet.

The transport layer is now available as the library module
`research_fetcher`. It is policy-gated, uses `reqwest` with Rustls, disables
proxy and redirects, pins a validated public DNS result for the request, and
streams responses through the configured byte limit. It is not wired into a
long-running gateway process yet; that integration remains a separately
reviewed step.

The planned local TLS test harness and its acceptance criteria are documented
in [TLS_TEST_HARNESS_PLAN.md](TLS_TEST_HARNESS_PLAN.md).

The first gateway process is available for controlled configuration testing:

```bash
cargo run --bin viper-research-gateway -- /tmp/viper-research-gateway.sock \
  examples/research-gateway.toml
```

`FETCH` is always policy-gated and live. `SEARCH` is opt-in: with no
`[search]` table in the gateway config (the case above) it returns
`ERR_NOT_IMPLEMENTED`, unchanged from before. Adding a `[search]` table
enables the Brave Search API as a provider; the design, the DuckDuckGo
evaluation that led to choosing Brave instead, and the new error codes are
documented in [SEARCH_PROVIDER_PLAN.md](SEARCH_PROVIDER_PLAN.md):

```bash
export BRAVE_SEARCH_API_KEY="..."
cargo run --bin viper-research-gateway -- /tmp/viper-research-gateway.sock \
  examples/research-gateway-with-search.toml
```

The key is read from the environment at startup and never written to a
config file or returned to a caller; a configured provider with an unset or
empty key variable is a startup error, not a silently disabled feature.

### Model gateway

A separate gateway process and socket, matching the `MODEL:*` gateway
namespace manifests already reference (`VIPER_LOCAL_OLLAMA_V1`). Its design
is documented in [MODEL_GATEWAY_PLAN.md](MODEL_GATEWAY_PLAN.md). Four
providers are supported — `ollama` (local, no key), and keyed `openai`,
`anthropic`, and `openrouter` (each reads its API key from an
`api_key_env`-named environment variable at startup, same pattern as Brave
Search). Each provider runs as its own gateway process;
`examples/model-gateway-openai.toml`, `examples/model-gateway-anthropic.toml`,
and `examples/model-gateway-openrouter.toml` are ready-to-run configs.

```bash
cargo build --bins
cargo run --bin viper-model-gateway -- /tmp/viper-model-gateway.sock \
  examples/model-gateway.toml
```

It requires a local Ollama instance (`http://127.0.0.1:11434` by default,
see `examples/model-gateway.toml`). Successful responses are classified
`MODEL_OUTPUT`, matching `GATEWAY_CONTRACT.md`; a model's output is never
pre-classified as trusted. Generation length is bounded server-side by
`max_output_tokens`, and `max_requests` is enforced the same way as the
research gateway's shared budget. `examples/gateway-registry.toml` maps
`VIPER_LOCAL_OLLAMA_V1` to this gateway's socket so `viper-helper` can
bind-mount it into a Box the same way it already does for the research
gateway.

`MODEL_GENERATE` is always live. `EMBED` is opt-in, same pattern as
`SEARCH`: with no `[embed]` table (the config above) it returns
`ERR_NOT_IMPLEMENTED`. Embedding-capable models are distinct from
generation models — Ollama gates this by the model's declared `embedding`
capability, not a server flag, so a chat model like `mistral:7b` fails
per-call with `ERR_EMBED_FAILED` rather than at startup:

```bash
ollama pull nomic-embed-text
cargo run --bin viper-model-gateway -- /tmp/viper-model-gateway.sock \
  examples/model-gateway-with-embed.toml
```

`EMBED` is also implemented for `openai` and `openrouter` — one shared
transport, since OpenRouter's own OpenAPI spec documents the same
`data[].embedding` response shape OpenAI uses, confirmed rather than
assumed. `examples/model-gateway-openai-with-embed.toml` and
`examples/model-gateway-openrouter-with-embed.toml` are ready-to-run
configs. `anthropic` has no public embeddings API at all — `[embed]` with
`provider = "anthropic"` is rejected at config load, not left to fail on
the first real call.

Token-by-token streaming is implemented for all four providers: `stream:
true` as a flag on `MODEL_GENERATE` (not a new method — every real
provider models it this way), a new `StreamChunk` frame sequence over the
same JSON-lines Unix socket, and an idle-chunk timeout plus an absolute
max-stream-duration cap a one-shot request never needed. `Response` and
`send_request` are untouched; every non-streaming caller keeps working
exactly as before. `openai`/`openrouter` stream as Server-Sent Events
(`data: {...}` lines ending in a literal `data: [DONE]`), including
OpenRouter's `:`-prefixed keep-alive comments and its mid-stream
`error`-field failure shape. `anthropic` streams typed SSE events
(`event: content_block_delta`/`message_stop`, no `[DONE]` sentinel) — a
genuinely different parser, verified against Anthropic's own published
streaming example before writing it. Full design and verification results
are in [STREAM_PLAN.md](STREAM_PLAN.md).

```bash
ollama pull mistral:7b
cargo run --bin viper-model-gateway -- /tmp/viper-model-gateway.sock \
  examples/model-gateway-with-stream.toml
# or examples/model-gateway-{openai,anthropic,openrouter}-with-stream.toml
```

A client sends `MODEL_GENERATE` with `"params": {"prompt": "...", "stream":
true}` and reads `StreamChunk` frames off the same connection until one
arrives with `done: true` (`ipc::send_streaming_request` does this).
Without a `[stream]` table (the base `examples/model-gateway.toml`) a
streaming request still gets back one `done: true` chunk, carrying
`ERR_NOT_IMPLEMENTED` — the wire contract stays symmetric even for an
immediate failure.

## Backend decision

The first real backend path is the separate `viper-helper` systemd-user helper
using systemd lifecycle, cgroups, and namespace controls for fixed controlled
test units. The decision and profile mapping are documented in
[BACKEND_DECISION.md](BACKEND_DECISION.md).

## Additional references

See [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md),
[ROADMAP.md](ROADMAP.md), [PROJECT_PLAN.md](PROJECT_PLAN.md), and
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for trade-offs confirmed real but
deliberately left unfixed at this alpha stage.

## Contact

Project owner: jarohull-ai  
Contact: venom.evo@protonmail.com
