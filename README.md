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
