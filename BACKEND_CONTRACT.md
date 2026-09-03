# viper-boxd Backend Contract

Status: design contract, pre-implementation  
Version: `viper-boxd.backend.v0`

This document defines the interface between the trusted `viper-boxd` control
plane and an execution backend. It does not define a sandbox implementation.
The first implementation may use Linux namespaces, systemd/cgroups, or a
supported sandbox tool, but it must satisfy this contract.

## 1. Scope and non-goals

The backend is responsible for creating and supervising an isolated process.
It is responsible for enforcement, not policy authoring. `viper-boxd` first
validates the JFP manifest and resolves an administrator-owned profile; only
then may it call the backend.

The backend is not:

- an agent-facing API,
- a profile registry,
- a policy decision-maker,
- a gateway for model or web traffic,
- a patch applier.

No operation in this contract may silently degrade to an unenforced mode.

## 2. Trust boundary

### Trusted components

- the `viper-boxd` daemon and its pinned JFP Box validator;
- the backend implementation and its system service boundary;
- administrator-owned profile and workspace registries;
- the operating system kernel, service manager, cgroup controller, and audit
  sink, within their documented guarantees.

### Untrusted inputs

- agents, workspaces, UIs, and schedulers requesting a Box;
- manifest contents and evidence obtained from the Internet;
- all child-process output;
- requested identifiers until resolved against trusted registries.

Agents never invoke the backend directly. They cannot provide host paths,
mount flags, namespace flags, Linux capabilities, credentials, PIDs, or
backend command-line arguments.

### Invocation rule

Only the local `viper-boxd` daemon may invoke this interface. The backend must
reject calls from any other principal or transport peer. A backend may be
implemented as an in-process module initially, but the same authorization
boundary must remain explicit.

## 3. Authoritative configuration

Profiles are loaded only from an administrator-controlled, non-agent-writable
directory. A profile is selected by immutable `profile_id`; callers cannot
submit or modify profile contents.

The profile resolver must verify, before `spawn`:

1. profile schema and version;
2. profile ownership and file permissions;
3. profile integrity metadata, when configured;
4. workspace-to-host-path mapping;
5. requested backend capabilities;
6. resource and lifecycle limits.

The backend receives the resolved, typed execution specification—not the raw
agent request and not arbitrary host paths.

## 4. Logical request and result

The transport is implementation-defined. The canonical logical shapes are:

```json
{
  "schema": "viper-boxd.backend.v0",
  "operation": "SPAWN",
  "task_id": "TASK_001",
  "box_id": "BOX_001",
  "workspace_id": "WORKSPACE_A",
  "profile_id": "RESEARCH_READONLY_V1",
  "audit_trace_id": "…",
  "executable": "trusted-agent-entrypoint",
  "argv": [],
  "mounts": [
    {"source_ref": "workspace", "target": "/work", "mode": "READ_ONLY"},
    {"source_ref": "scratch", "target": "/scratch", "mode": "READ_WRITE"}
  ],
  "network": {"mode": "GATEWAY_ONLY", "gateway_refs": []},
  "limits": {
    "cpu_quota_us": 100000,
    "memory_limit_bytes": 1073741824,
    "ttl_seconds": 300
  }
}
```

`source_ref` values are resolved by trusted configuration. Literal host paths
are not valid on this interface. `executable` must resolve from an approved
registry; arbitrary shell commands are not supported.

Every successful operation returns a structured result containing at least:
`schema`, `box_id`, `audit_trace_id`, `status`, and (for a running Box) an
opaque backend handle. Handles and PIDs are never accepted from agents.

## 5. Required operations

### `SPAWN`

Creates one isolated Box from a previously resolved specification.

Required behavior:

- verify the caller and request schema;
- verify all requested capabilities are available and enforceable;
- create private process, mount, and network isolation as requested by the
  profile;
- apply CPU, memory, and TTL limits before the child can execute;
- mount only resolved paths with the declared modes;
- return `STARTING` or `RUNNING` with an opaque handle;
- emit a spawn audit event.

If any control cannot be applied before execution, return an error and do not
start the child.

### `STATUS`

Returns the lifecycle state and observed resource/termination information for
an existing backend handle. It must not broaden access or change policy.

Allowed states are `STARTING`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMED_OUT`,
`KILLED`, and `CONTAINMENT_BREACH`.

### `KILL`

Terminates the Box and all descendants, using the strongest available
process-group/cgroup mechanism. It is idempotent: an already terminated Box
returns its final state.

### `CLEANUP`

Releases cgroups, namespaces, handles, and temporary scratch state after the
Box has stopped. Cleanup must be idempotent and must never delete a path
outside the resolved Box scratch directory. Failure to prove cleanup completes
is an error and must be audited.

`CLEANUP` does not apply patches to `/work`; that is a separate deterministic
output/patch-applier stage.

## 6. Error contract

Errors are stable machine-readable codes with a human-readable message and
the related `operation`, `box_id` (when known), and `audit_trace_id`.

| Code | Meaning | Required action |
| --- | --- | --- |
| `ERR_UNAUTHORIZED_CALLER` | Caller is not the viper-boxd trust principal | Reject; audit |
| `ERR_INVALID_REQUEST` | Malformed or incomplete backend request | Reject; do not spawn |
| `ERR_UNSUPPORTED_SCHEMA` | Unknown backend contract version | Reject; do not spawn |
| `ERR_PROFILE_UNAVAILABLE` | Profile missing, unreadable, or expired | Reject; do not spawn |
| `ERR_PROFILE_INTEGRITY` | Profile ownership, permissions, or integrity check failed | Reject; do not spawn |
| `ERR_WORKSPACE_RESOLUTION` | Workspace reference cannot be safely resolved | Reject; do not spawn |
| `ERR_CAPABILITY_UNAVAILABLE` | Requested isolation control is unavailable | Fail closed; do not spawn |
| `ERR_CAPABILITY_UNENFORCEABLE` | Control was requested but could not be applied | Fail closed; do not spawn |
| `ERR_MOUNT_SETUP` | A required mount or access mode failed | Terminate/cleanup; audit |
| `ERR_NETWORK_SETUP` | Network namespace or gateway restriction failed | Terminate/cleanup; audit |
| `ERR_LIMIT_SETUP` | CPU, memory, or TTL limit was not active before start | Do not spawn |
| `ERR_EXECUTION_START` | Child could not be started safely | Cleanup; audit |
| `ERR_HANDLE_UNKNOWN` | Box handle is unknown or already invalid | Return error; do not guess |
| `ERR_KILL_FAILED` | Required termination did not complete | Escalate; mark failure |
| `ERR_CLEANUP_FAILED` | Resources or scratch state remain | Mark `CONTAINMENT_BREACH`; audit |
| `ERR_AUDIT_FAILED` | Required audit event could not be persisted | Fail closed; stop or do not spawn |
| `ERR_INTERNAL` | Unexpected backend failure | Fail closed; never retry permissively |

An error is not permission to retry with weaker isolation. Retries must use the
same immutable profile and may occur only after safe cleanup or explicit
operator review.

## 7. System requirements

The backend must report capabilities before accepting a spawn. At minimum, a
Linux implementation must document support for:

- process isolation (`clone`/`clone3` or an equivalent trusted mechanism);
- mount namespace creation and read-only/read-write mount enforcement;
- network namespace or an equivalent gateway-only network boundary;
- cgroup CPU, memory, and lifecycle controls;
- descendant termination and reliable cleanup;
- an authenticated local IPC or system-service boundary;
- monotonic-clock based TTL enforcement;
- audit event delivery.

Depending on deployment, mount and namespace setup may require a small system
service with narrowly scoped privileges (often including `CAP_SYS_ADMIN`,
network namespace privileges, and cgroup delegation). Those capabilities must
belong to the trusted helper, never to the agent process. The exact capability
set is backend-specific and must be measured and documented; broad
`--privileged` execution is prohibited.

Unprivileged user namespaces, bubblewrap, Firejail, or nsjail may be used only
when capability detection confirms that the requested controls are actually
enforced. A setuid workaround is not assumed or enabled by this contract.

## 8. Fail-closed invariants

The backend must refuse to spawn when:

- JFP validation is absent or not `PLAN_ACCEPTED`;
- profile and manifest identifiers or policies do not match;
- any requested mount, network, capability, or limit cannot be enforced;
- authentication, profile resolution, or required audit persistence fails;
- the backend cannot prove that the child will start inside the requested
  boundary.

There is no permissive fallback to the host filesystem, direct network,
unbounded resources, or the caller's environment.

## 9. Lifecycle and audit requirements

The control plane records at least:

```text
REQUESTED → VALIDATED → PROFILE_RESOLVED → SPAWNED → RUNNING
          → {COMPLETED | FAILED | TIMED_OUT | KILLED | CONTAINMENT_BREACH}
          → CLEANED
```

Each transition carries `task_id`, `box_id`, `workspace_id`, `profile_id`,
`audit_trace_id`, timestamp, backend identifier, and outcome/error code.
The backend must not report `RUNNING` until all mandatory controls are active.

## 10. Verification gate before implementation

The first backend implementation may begin only after tests demonstrate:

1. unauthorized callers are rejected;
2. missing capabilities fail closed;
3. mounts have the declared visibility and write modes;
4. direct network is unavailable when denied;
5. CPU, memory, and TTL limits are active before execution;
6. kill reaches descendants;
7. cleanup is idempotent and confined to scratch;
8. every failure produces an audit event;
9. no test requires an agent to possess a privileged capability.

This contract is a prerequisite for implementation, not evidence that a
backend or sandbox already exists.
