# RESEARCH_GATEWAY — controlled fetch plan v0.1

This document defines the first real gateway boundary before any live HTTP
transport is enabled. The gateway is a separate trusted process; a Box never
gets direct network access or provider credentials.

## Policy contract

Configuration comes from an administrator-owned file, never from a Box or an
agent request:

```toml
schema = "viper-boxd.research-gateway.v0"
gateway_id = "RESEARCH_PUBLIC_WEB_V1"
allowed_domains = ["example.org"]
max_requests = 30
max_fetch_bytes = 5242880
max_redirects = 0
timeout_seconds = 10
```

The gateway accepts only `SEARCH` and `FETCH` requests from the versioned
Unix-socket contract. `FETCH` requires an HTTPS URL whose hostname is in the
administrator allowlist. The caller cannot override limits, headers, proxy
settings, DNS servers, or redirect policy.

## Mandatory protections

- reject localhost, loopback, link-local, multicast, RFC1918 and other private
  address ranges after DNS resolution;
- reject redirects in the first implementation;
- allow only HTTPS and safe read operations;
- enforce request count, response bytes, timeout and content-type limits;
- strip active HTML elements before returning text;
- return URL, timestamp, HTTP status, byte count and content hash;
- classify every fetched item as `UNTRUSTED_EVIDENCE`;
- never forward cookies, authorization headers, API keys or agent metadata;
- fail closed when a protection cannot be enforced.

## Acceptance tests before live transport

The implementation must reject malformed URLs, non-HTTPS schemes, hosts not in
the allowlist, localhost/private addresses, redirects, oversized responses,
expired budgets and unsupported methods. Tests must also prove that secrets and
caller-supplied transport options are ignored. Only after these tests pass may
an external provider be configured.

This plan intentionally does not claim that the gateway is implemented yet.
