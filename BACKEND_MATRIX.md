# Backend Capability Matrix

`viper-boxd` selects a backend only after checking that it can enforce every
control required by the resolved profile. Missing capabilities cause refusal.

| Capability | system service | bubblewrap | Firejail | nsjail |
| --- | --- | --- | --- | --- |
| mount/filesystem isolation | planned | conditional on userns | profile-dependent | supported |
| network namespace | planned | conditional | supported | supported |
| CPU/memory/TTL | systemd/cgroups | external supervisor | partial | partial |
| seccomp | explicit configuration | limited by wrapper | supported | supported |
| privilege separation | explicit service user | user namespace | profile-dependent | explicit |

This table is a planning aid, not a security certification. Runtime probing and
integration tests must verify actual kernel and distribution behavior.

## Fail-closed rules

- no silent fallback to an unrestricted process;
- no SUID workaround without an explicit administrator decision and review;
- unsupported `NETWORK_MODE`, mount, seccomp, or resource requirement means
  `REJECTED`;
- backend arguments are generated from trusted profiles, never copied from an
  agent request.
