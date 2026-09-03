# viper-boxd Roadmap

## Phase 0 — Design (current)

- freeze trust boundaries and request schema;
- define profile registry and backend capability matrix;
- document failure-closed behavior and audit events;
- decide IPC mechanism and privilege model.

## Phase 1 — Non-privileged simulator

- `viper-boxd plan` consumes logical IDs only;
- emits the exact mounts, limits, gateways, and audit plan;
- never starts a process;
- golden tests for every network mode and rejection path.

## Phase 2 — Minimal trusted supervisor

- execute a harmless test process only;
- enforce TTL and resource limits;
- prove workspace and HOME isolation;
- structured lifecycle and cleanup tests.

## Phase 3 — Gateway mediation

- MODEL and RESEARCH gateway contracts;
- request quotas, destination validation, evidence classification;
- secret isolation and end-to-end audit correlation.

## Phase 4 — Controlled agent execution

- one approved agent profile;
- adversarial testing and independent review;
- deterministic patch applier integration;
- documented operational runbook.

## Phase 5 — Production readiness

- portability matrix and backend capability reporting;
- external security assessment;
- reproducible release artifacts;
- stable API only after real-world evidence.
