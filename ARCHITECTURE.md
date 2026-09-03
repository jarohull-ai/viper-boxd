# viper-boxd Architecture

## Trust model

The daemon is a small, privileged control-plane component. It receives only
logical identifiers and a validator result. Trusted configuration is loaded
from an administrator-controlled directory; it is never supplied by an agent.

## Planned components

1. **IPC/API boundary** — authenticated requests containing `task_id`,
   `workspace_id`, `profile_id`, and the manifest bytes or hash.
2. **Policy gate adapter** — invokes the pinned JFP Box validator and rejects
   any non-`PLAN_ACCEPTED` result.
3. **Profile resolver** — maps immutable profile IDs to approved mounts,
   capabilities, limits, and gateway bindings.
4. **Execution supervisor** — creates a process, applies backend isolation,
   enforces TTL/resource limits, and terminates reliably.
5. **Gateway broker** — exposes only typed operations such as `MODEL_GENERATE`,
   `SEARCH`, and `FETCH`; secrets remain outside the Box.
6. **Output gate** — accepts structured JFP output and hands proposed changes
   to a separate deterministic patch applier.
7. **Audit sink** — records spawn, policy, gateway, limit, outcome, and cleanup
   events under one `AUDIT_TRACE_ID`.

## Backend abstraction

The policy contract must not depend on one sandbox implementation. Candidate
backends include a system service using mount/network namespaces, systemd
resource controls, seccomp, and—where supported—bubblewrap, Firejail, or
nsjail. Backend capability detection must fail closed when a requested control
cannot be enforced.

## Data flow

```text
request → authenticate → validate manifest → resolve trusted profile
        → create isolated execution → mediate gateways → validate output
        → persist audit → terminate and clean up
```
