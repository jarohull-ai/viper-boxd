# Policy Profiles

Profiles are immutable, administrator-controlled records referenced by
`profile_id`. A request selects a profile; it cannot define one.

| Profile | Direct network | Gateways | Typical use |
| --- | --- | --- | --- |
| `OFFLINE_STRICT_V1` | denied | none | local analysis |
| `MODEL_ONLY_V1` | denied | model gateway only | reasoning without web access |
| `RESEARCH_READONLY_V1` | denied | model + research gateway | controlled OSINT |
| `NETWORK_RESTRICTED_V1` | denied | explicit service allowlist | approved APIs |

Every profile defines allowed tools, resource limits, writable scratch scope,
TTL, output schema, evidence class, and required backend capabilities.

## Research pipeline

Research execution produces `UNTRUSTED_EVIDENCE` with URL, timestamp, status,
content hash, and sanitized text. A separate offline or model-only Box may
consume that evidence. Untrusted content never changes policy or becomes a
system instruction.

## Profile change control

Profile files require ownership, version, integrity metadata, and review. A
profile change is a policy change and must produce a new immutable ID or an
explicitly versioned revision.
