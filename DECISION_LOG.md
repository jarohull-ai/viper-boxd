# Architecture Decision Log

## ADR-001 — Separate validator and runner

**Decision:** Keep JFP Box policy validation independent from `viper-boxd`.

**Reason:** The validator is small and portable; runtime enforcement needs
privileges, kernel-specific code, and a separate security review.

## ADR-002 — Logical identifiers only

**Decision:** Requests contain `workspace_id` and `profile_id`, never host paths
or sandbox flags.

**Reason:** Prevents agents from selecting broader filesystem or capability
authority than the administrator intended.

## ADR-003 — Fail closed on unsupported controls

**Decision:** Refuse execution when the selected backend cannot enforce a
requested policy control.

**Reason:** A declared restriction that is not enforced is a misleading and
unsafe security boundary.

## ADR-004 — Gateways instead of direct network

**Decision:** Network access is mediated by typed, auditable gateways.

**Reason:** This isolates credentials and allows quotas, destination checks,
evidence classification, and policy enforcement at one boundary.

## ADR-005 — Patch application outside the Box

**Decision:** Agents produce structured proposed changes; a deterministic,
non-LLM applier modifies the workspace.

**Reason:** It minimizes the trusted computing base that can write project
files and makes review and rollback practical.
