# viper-boxd Threat Model

## Assets

- host filesystem and credentials;
- workspace separation and project integrity;
- model/provider API keys;
- gateway audit records;
- integrity of JFP manifests and output artifacts.

## Threat classes

- **P1 — agent error:** loops, malformed output, accidental wrong file;
- **P2 — untrusted content:** prompt injection, poisoned web evidence, social
  engineering;
- **P3 — hostile code:** exploit attempts, privilege escalation, sandbox escape.

The validator addresses policy consistency and reduces P1/P2 exposure. P3
requires the operating system, backend, privilege separation, and independent
security review.

## Required invariants

- default-deny direct network;
- no agent-controlled host paths or backend flags;
- one Box maps to exactly one workspace identity;
- writes go to scratch until a non-LLM output gate approves a patch;
- gateway and model secrets never enter the Box;
- unsupported backend controls cause fail-closed refusal;
- every lifecycle transition is auditable and tied to `AUDIT_TRACE_ID`.

## Explicit limitations

This document is a design target, not evidence that the future daemon already
provides these guarantees.
