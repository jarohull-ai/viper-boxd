# SEARCH provider — implementation contract

## Why this exists

`viper-research-gateway` has always returned `ERR_NOT_IMPLEMENTED` for
`SEARCH`. DuckDuckGo's free Instant Answer API was evaluated and rejected: it
only returns knowledge-graph snippets for topics it recognizes and returns
empty results for ordinary queries (verified against the live endpoint, e.g.
`q=warszawa` returns a heading, `q=rust+programming` returns nothing). Wiring
it up as `SEARCH` would silently return empty evidence for most real queries,
which is worse than the current explicit `ERR_NOT_IMPLEMENTED`. Scraping
DuckDuckGo's HTML result page was rejected as out of character for this
project: unofficial, against their terms, and fragile.

## Chosen provider

Brave Search API (`api.search.brave.com`), a keyed JSON API with a free tier.
It is opt-in and administrator-configured; the caller (a Box) never sees or
supplies the key, matching the existing FETCH secret-isolation posture.

## Configuration

`GatewayConfig` gains an optional `[search]` table. Its absence disables
`SEARCH` exactly as today (`ERR_NOT_IMPLEMENTED`), so the existing
`examples/research-gateway.toml` and its tests are unaffected.

```toml
[search]
provider = "brave"
api_key_env = "BRAVE_SEARCH_API_KEY"
```

The gateway reads the named environment variable at startup, never from the
config file itself. A configured provider whose key environment variable is
absent or empty is a startup error (fail closed), not a silently disabled
feature.

## Request/response contract

No new caller-facing surface: `SEARCH` already takes `params.query` per
`GATEWAY_CONTRACT.md`. The caller cannot supply a provider, endpoint, header,
or result count. A successful response has the same shape the mock gateway
already returns:

```json
{"gateway": "...", "evidence_class": "UNTRUSTED_EVIDENCE", "query": "...", "results": [{"title": "...", "url": "...", "snippet": "..."}]}
```

Titles and snippets are sanitized with the existing `sanitize_html`. Result
count is fixed by the gateway (not caller-controlled). `SEARCH` consumes the
same `max_requests` budget as `FETCH`, checked before any outbound call.

## Transport seam

Mirrors `research_fetcher::HttpTransport`: a `SearchTransport` trait isolates
the real HTTP call (`reqwest` + Rustls, redirects disabled, no proxy, fixed
timeout) from response parsing and validation, so parsing/error-mapping is
unit-testable with a canned transport and no live key or network call.

## New error codes

| Code | Meaning |
| --- | --- |
| `ERR_SEARCH_QUERY_INVALID` | `params.query` missing, empty, or unreasonably long |
| `ERR_SEARCH_FAILED` | Transport-level failure (DNS/connect/timeout/non-2xx) |
| `ERR_SEARCH_RESPONSE_INVALID` | Provider response was not the expected JSON shape |

`ERR_NOT_IMPLEMENTED` remains the response when no `[search]` provider is
configured, and `ERR_REQUEST_LIMIT_EXCEEDED` remains shared with `FETCH`.

## Acceptance tests before this is considered done

- query validation rejects empty/oversized queries without any network call;
- a canned successful provider response maps to the documented shape with
  `UNTRUSTED_EVIDENCE`, sanitized text, and no raw provider fields leaked;
- a canned error/malformed response maps to a stable error code;
- the request budget is consumed before the transport call, same as FETCH;
- with no `[search]` table configured, `SEARCH` still returns
  `ERR_NOT_IMPLEMENTED` (no behavior change to the existing example config);
- `cargo test --locked`, Clippy, and `cargo audit` all pass.

## Explicitly out of scope here

- DuckDuckGo and Google Custom Search remain possible future
  `SearchTransport` implementations behind the same trait; neither is
  implemented now.
- A live end-to-end call against the real Brave endpoint requires an
  operator-supplied `BRAVE_SEARCH_API_KEY` and is not part of the automated
  test suite.
