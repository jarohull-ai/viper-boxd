# viper-boxd

**Trusted execution daemon for JFP Box policies — design phase**

> This repository is private by design. It contains architecture and planning
> material for the future runtime layer; it is not an executable sandbox yet.

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

## Status

Design-only, private, pre-alpha. See [ARCHITECTURE.md](ARCHITECTURE.md),
[THREAT_MODEL.md](THREAT_MODEL.md), [ROADMAP.md](ROADMAP.md), and
[PROJECT_PLAN.md](PROJECT_PLAN.md).

## Contact

Project owner: jarohull-ai  
Contact: venom.evo@protonmail.com
