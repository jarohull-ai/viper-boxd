# Phase 0 Design Review

**Status:** baseline decisions recorded — 2026-09-03  
**Scope:** architecture and simulator only; no privileged runtime code.

## Decisions

### D1 — IPC: Unix domain socket first

The initial interface is a root-owned Unix socket with peer-credential checks.
Requests contain logical IDs and manifest bytes/hash only. D-Bus may be added
later if desktop integration requires it.

### D2 — Privilege separation

The future design separates an unprivileged request broker from the smallest
possible privileged helper. The helper receives a resolved, immutable execution
plan—not agent input—and exposes a narrow allowlisted operation set. The
simulator runs entirely unprivileged.

### D3 — First backend: Linux system service

The first implementation targets Linux with a systemd-managed service and
namespace/mount controls. Bubblewrap, Firejail, and nsjail remain optional
backends. No fallback to an unrestricted process is permitted.

### D4 — Profile format: versioned TOML

Administrator-controlled profiles use versioned TOML files. `profile_id` is
immutable and maps to workspace mounts, tools, gateways, limits, and required
backend capabilities. Agents cannot create or edit profiles.

### D5 — Audit: append-only structured events

The daemon emits JSON Lines events keyed by `audit_trace_id`. Secrets, prompts,
cookies, and raw credentials are excluded. Audit failure prevents a new spawn
and is itself recorded where possible.

### D6 — Output: structured proposal, separate applier

An executed Box writes only to scratch and returns a validated output envelope.
Workspace changes are represented as a patch manifest and applied by a
separate deterministic, non-LLM component.

## Simulator acceptance criteria

- accepts only logical identifiers;
- invokes the pinned JFP validator;
- resolves profiles deterministically;
- prints the complete backend plan as JSON;
- performs no mounts, network changes, process spawns, or file mutations;
- reports unsupported controls as explicit fail-closed errors;
- produces deterministic audit fields for identical inputs.

## Deferred decisions

- exact systemd unit hardening and helper transport;
- supported distribution/kernel matrix;
- gateway authentication and quota protocol;
- patch manifest schema and rollback format;
- independent review plan for privileged code.

These decisions are intentionally deferred until simulator fixtures expose the
required behavior.
