# viper-boxd Interfaces

## Spawn request

The first interface is logical and versioned. Agents and UIs may provide only
identifiers and the manifest bytes or its hash:

```json
{
  "schema": "viper-boxd.spawn_request.v0",
  "task_id": "TASK_001",
  "workspace_id": "WORKSPACE_A",
  "profile_id": "RESEARCH_READONLY_V1",
  "manifest_sha256": "...",
  "manifest": "..."
}
```

Host paths, ports, capabilities, credentials, and sandbox command-line flags
are never valid request fields.

## Outcome

```json
{
  "schema": "viper-boxd.outcome.v0",
  "task_id": "TASK_001",
  "box_id": "BOX_...",
  "status": "COMPLETED",
  "audit_trace_id": "...",
  "output_ref": "scratch://...",
  "reason": null
}
```

Possible statuses include `REJECTED`, `STARTING`, `RUNNING`, `COMPLETED`,
`TIMED_OUT`, `KILLED`, `FAILED`, and `CONTAINMENT_BREACH`.

## Compatibility

Unknown schema versions, fields that broaden authority, or missing required
identifiers must fail closed. IPC authentication and authorization are part of
the trusted daemon boundary, not agent responsibilities.
