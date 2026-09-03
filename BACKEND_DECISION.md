# Backend Decision Record

Status: approved design decision, pre-implementation  
Decision version: `viper-boxd.backend-decision.v0`

## Decision summary

The first real backend will use a two-process architecture:

```text
agent / UI
    │ logical identifiers only
    ▼
viper-boxd (unprivileged daemon)
    │ authenticated local IPC; resolved typed specification
    ▼
viper-helper (small system service)
    │ systemd system manager / cgroups / namespaces
    ▼
isolated child process
```

`viper-boxd` remains the policy and orchestration boundary. `viper-helper` is
the only component allowed to perform privileged setup. The agent never talks
to either component directly.

## 1. Isolation mechanism

### Chosen for the first backend: systemd system service

The helper will create a transient system service or scope with properties
derived from the trusted execution specification. The exact property set will
be capability-probed and tested before each supported deployment.

Planned controls include:

| Contract control | systemd mechanism (subject to probe) |
| --- | --- |
| process lifecycle | transient unit, service manager supervision |
| CPU limit | `CPUQuota=` / cgroup CPU controller |
| RAM limit | `MemoryMax=` / cgroup memory controller |
| TTL | helper watchdog plus unit timeout; monotonic deadline |
| private `/tmp` | `PrivateTmp=` |
| home/secret protection | `ProtectHome=` and explicit path policy |
| read-only system paths | `ProtectSystem=` |
| writable scratch only | `ReadWritePaths=` with resolved scratch path |
| mount visibility | `PrivateMounts=` and approved bind-path properties |
| network isolation | `PrivateNetwork=` or explicit gateway-only network setup |
| descendant cleanup | unit/cgroup stop operation |

Systemd is selected because it provides a mature lifecycle and cgroup
interface while keeping privileged code small. The helper must refuse a
profile if the installed systemd version cannot enforce a requested property.
The table is a design mapping, not a claim that these controls are active on
the current host.

### Rejected as the first implementation

#### Direct `clone()`/`clone3()` in viper-boxd

Rejected for the first backend because it would put unsafe, privileged,
low-level namespace and mount code in the main daemon. It remains a possible
future backend after the helper IPC boundary, independent review, and dedicated
integration tests exist.

#### Bubblewrap as the mandatory backend

Rejected as a requirement because user namespace availability varies and is
currently not an enforcement guarantee on this host. Bubblewrap may be an
optional backend when the capability probe proves the required mode and the
administrator explicitly enables it. A setuid workaround is not assumed.

## 2. Privilege separation

`viper-boxd` will run as an ordinary service user. It may:

- authenticate requests;
- invoke the pinned JFP validator;
- resolve immutable profiles and workspace references;
- send a typed specification to the helper;
- consume lifecycle and audit results.

`viper-helper` will run as a dedicated system service identity. It may only:

- authenticate the `viper-boxd` peer;
- validate the backend contract version;
- resolve already-authorized references supplied by the daemon;
- create and supervise the isolated unit;
- return opaque handles and structured results.

The helper must not expose a generic command runner, shell, arbitrary mount
API, or arbitrary path API. Any Linux capabilities granted to it must be the
smallest set required by the selected systemd configuration and documented by
the deployment. The child receives none of the helper's privileged
capabilities.

## 3. Profile-to-backend mapping

Profiles remain administrator-owned TOML. The daemon compiles them into a
typed specification; agents cannot supply systemd properties.

| Profile field | Resolved backend value | Validation rule |
| --- | --- | --- |
| `workspace_id` | registry-owned workspace path | never caller-supplied as a path |
| `profile_id` | immutable profile record | must exist and pass integrity checks |
| `write_target = "scratch"` | per-Box scratch directory | only writable mount |
| `required_backend` | capability requirements | every item must be enforceable |
| `execution_ttl_seconds` | bounded unit deadline/watchdog | must be positive and within policy maximum |
| `memory_limit_bytes` | `MemoryMax=` | must be supported before spawn |
| `network_mode` | private or gateway-only network profile | no direct network fallback |
| `direct_network = "DENY"` | no unrestricted egress | mandatory invariant |
| `allowed_gateways` | gateway references, not sockets/URLs | resolved by trusted gateway registry |
| `read_paths` | approved read-only bind paths | no arbitrary host path |
| `required_backend` | systemd feature set | missing capability means reject |

The first implementation supports only profiles whose `required_backend` can
be mapped completely. Partial mapping is an error, not a warning.

## 4. Network decision

The first backend will support `DIRECT_NETWORK:DENY` as the only safe default.
`OFFLINE_STRICT` may use a private network namespace with no interfaces.
`MODEL_ONLY` and `RESEARCH` require a separately designed gateway path; they
must not receive unrestricted loopback or host networking. If gateway-only
networking cannot be enforced by the selected systemd deployment, those
profiles are rejected until a gateway backend exists.

## 5. Required implementation order

1. Implement and test authenticated helper IPC using fixed typed messages.
2. Add systemd capability detection for every property used by a profile.
3. Implement a harmless child (`/usr/bin/true`-class test executable) with no
   project mounts and verify lifecycle/cleanup.
4. Add read-only workspace and scratch mounts.
5. Add network denial and then gateway-only networking.
6. Add negative tests for every missing or unenforceable control.
7. Perform independent security review before any real agent executable is
   allowed.

No production agent will be run until steps 1–6 are green.

## 6. Decision consequences

Benefits:

- privileged code is isolated from policy parsing and agent input;
- lifecycle, cgroups, and descendant cleanup use a mature system service;
- the backend remains replaceable behind the existing contract;
- no setuid bubblewrap dependency is introduced.

Costs and residual risks:

- systemd is a Linux/systemd deployment requirement for backend v0;
- systemd property semantics vary by version and must be probed;
- gateway-only networking is a separate component, not solved by this record;
- a system service remains security-sensitive and requires review.

This decision authorizes design and test scaffolding. It does not by itself
authorize a permissive fallback or claim that isolation is already available.
