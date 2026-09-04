# viper-boxd

**Trusted execution daemon for JFP Box policies — simulator phase**

> This repository is private by design. The current binary is an unprivileged
> simulator; it is not an executable sandbox or runtime yet.

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

## Non-goals for the design phase

- no agent execution;
- no direct handling of model or provider API keys;
- no arbitrary host-path or sandbox-flag input from agents;
- no claim of kernel-level security until an implementation is independently
  reviewed and tested.

## Relationship to JFP Box

`viper-boxd` must treat the JFP validator as a mandatory policy gate, but a
`PLAN_ACCEPTED` result is necessary—not sufficient—for safe execution. The
daemon owns the mapping from logical `workspace_id` and `profile_id` to trusted
host configuration. Agents never provide host paths, capabilities, ports, or
backend arguments.

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

## Backend decision

The planned first real backend is a separate `viper-helper` system service
using systemd lifecycle, cgroups, and namespace controls. The decision and
profile mapping are documented in [BACKEND_DECISION.md](BACKEND_DECISION.md).
No privileged runner has been implemented yet.

## Status

Working unprivileged simulator, private, pre-alpha. See [ARCHITECTURE.md](ARCHITECTURE.md),
[THREAT_MODEL.md](THREAT_MODEL.md), [ROADMAP.md](ROADMAP.md), and
[PROJECT_PLAN.md](PROJECT_PLAN.md).

## Contact

Project owner: jarohull-ai  
Contact: venom.evo@protonmail.com
