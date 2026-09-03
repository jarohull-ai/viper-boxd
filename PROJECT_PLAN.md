# viper-boxd Project Plan

## Principles

1. Policy before execution.
2. Logical identities before host paths.
3. Default deny and fail closed.
4. Small trusted core, separate untrusted tools.
5. Evidence and proposed changes are data, never instructions.
6. Every security claim requires a reproducible test.

## First implementation milestones

### M1 — Contract

- versioned spawn request and outcome schemas;
- profile registry format;
- backend capability declaration;
- audit event schema.

### M2 — Simulator

- deterministic plan generation;
- no process or mount side effects;
- negative and property-based tests;
- CLI and machine-readable output.

### M3 — Supervisor prototype

- system service boundary;
- least-privilege child process;
- TTL, CPU, memory, and cleanup enforcement;
- explicit unsupported-feature errors.

### M4 — Security validation

- namespace and filesystem tests;
- network egress tests;
- secret exposure tests;
- crash/timeout/cleanup tests;
- threat-led review and documented residual risk.

## Exit criteria for public release

- no known high-severity findings in dependency and static analysis scans;
- reproducible integration tests on each supported backend;
- independent review of privilege and namespace code;
- clear operational limits and rollback procedure;
- public documentation that distinguishes guarantees from assumptions.

## Open decisions

- system service IPC: Unix socket vs. D-Bus;
- exact privilege separation and installation model;
- supported Linux distributions and kernel feature floor;
- gateway protocol and authentication;
- whether patch application is a separate repository.
