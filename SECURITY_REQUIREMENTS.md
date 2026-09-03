# Security Requirements

These are acceptance requirements for a future implementation, not claims
about the current design-only repository.

## Mandatory controls

- authenticate and authorize every IPC request;
- invoke a pinned JFP Box validator before every spawn;
- resolve workspace and profile IDs only from trusted configuration;
- run with least privilege and isolate the child process;
- deny direct network access unless a profile explicitly permits a gateway;
- expose typed gateway operations, never arbitrary HTTP or shell;
- make `/scratch` the only Box write target;
- enforce TTL, CPU, memory, output-size, and gateway quotas;
- validate and sanitize output before any patch application;
- emit auditable lifecycle events and guarantee cleanup.

## Failure behavior

Crashes, malformed responses, unavailable backends, capability mismatches,
expired profiles, and audit failures must stop execution or prevent spawn.
The daemon must never convert an enforcement failure into a permissive mode.

## Verification

Each control requires an automated integration test, a negative test, and a
documented residual risk. Privileged namespace and filesystem code requires
independent review before any public or production release.
