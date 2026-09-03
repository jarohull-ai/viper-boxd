# Audit Schema

Every request and lifecycle transition carries one `audit_trace_id`.
Records must be append-only from the daemon's perspective and must not include
secrets or raw credentials.

## Event shape

```json
{
  "schema": "viper-boxd.audit.v0",
  "event": "BOX_SPAWN_ACCEPTED",
  "occurred_at": "2026-09-03T00:00:00Z",
  "audit_trace_id": "...",
  "task_id": "TASK_001",
  "workspace_id": "WORKSPACE_A",
  "box_id": "BOX_...",
  "profile_id": "MODEL_ONLY_V1",
  "manifest_sha256": "...",
  "backend": "system-service",
  "result": "accepted",
  "reason_code": null
}
```

Required events: request received, validator result, profile resolved, spawn,
gateway call, limit reached, output accepted/rejected, termination, cleanup,
and containment breach.

Identifiers and hashes are retained; prompts, API keys, cookies, and sensitive
workspace content are excluded by default.
