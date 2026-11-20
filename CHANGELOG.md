# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The HTTP transport no longer exits on a malformed request (WYREAI-741).** The request
  target was parsed against the client-supplied `Host` header, and a value that does not parse
  (or a target such as `//`) threw inside the request listener before authentication. The
  target is now parsed against a fixed base, so `Host` is no longer consulted, and a target
  that still cannot be parsed gets a `400` JSON response while the server keeps running.

- Gateway mode now reads `X-Proofpoint-Cluster-Url`. `startHttpTransport` extracted `servicePrincipal`/`serviceSecret` from headers but hardcoded `baseUrl` from `PROOFPOINT_BASE_URL` (or the enterprise TAP default), ignoring any cluster URL the gateway sent — so a Proofpoint Essentials tenant or any non-default host silently got routed to the wrong API regardless of what was configured. The header is optional and still falls back to `PROOFPOINT_BASE_URL` / the default host, so single-tenant/env-mode deployments are unaffected. The credential-resolution logic that used to be inlined in the HTTP handler is now `resolveGatewayCredentials()` in `src/utils/client.ts`, covered by `src/__tests__/gateway-credentials.test.ts`.

- Custom base URLs with a path prefix no longer lose that prefix. `apiRequest()` built request URLs with `new URL(path, base)`, which performs RFC 3986 relative resolution rather than concatenation: because every call site passes a path-absolute reference (e.g. `/v2/campaign`), the base's own path was discarded. Proofpoint Essentials tenants require an `/api` prefix on `PROOFPOINT_BASE_URL` (e.g. `https://<tenant>.proofpointessentials.com/api/`), so every request 404'd against `/v2/…` instead of `/api/v2/…`. The base and path are now slash-normalized and joined explicitly. Enterprise TAP (`https://tap-api-v2.proofpoint.com`, no path segment) is unaffected, which is why the bug was invisible by default. Regression tests in `src/__tests__/client-url.test.ts` pin both host shapes. Thanks to @Glitch3dPenguin for the report and fix.

- Multi-client HTTP transport: the server now builds a fresh `Server` + stateless `StreamableHTTPServerTransport` per `/mcp` request instead of sharing one stateful transport (created with `sessionIdGenerator: () => randomUUID()`) across all requests. The shared stateful transport rejected every client after the first with `-32600 "Server already initialized"`, so behind the multi-user gateway only the first user since container start received any tools and everyone else saw zero tools until a restart. Per-request request handlers are now built by a `createFreshServer()` factory, the transport is stateless (no `sessionIdGenerator`), and each server + transport is disposed on response close. Per-request handling is wrapped in try/catch that responds `500 {-32603 Internal error}` (never rethrows) so a single failed request cannot crash the container. stdio mode still uses one long-lived server; gateway header/credential checks and per-request `AsyncLocalStorage` credential isolation are unchanged.
- `/health` no longer calls `getCredentials()` — it is now a shallow, unauthenticated liveness probe returning `200 {"status":"ok"}`. In gateway mode credentials only arrive per-request via headers, so the previous credential check always returned `503`, failing the Azure liveness probe and crash-looping the container. Also added `/healthz` as an alias.

### Added

- **Interactive threat card via MCP Apps (SEP-1865).** `proofpoint_threat_get_by_id` results now render as an interactive card in MCP Apps hosts (Claude Desktop/web, and other hosts advertising the `io.modelcontextprotocol/ui` extension), instead of a wall of JSON. The card shows the threat name, status, category, type, severity score, identification date, detection type, and the resolved actor / malware-family / campaign names from the TAP threat summary. The card is read-only — Proofpoint threat intelligence has no safe write round-trip to surface. Non-App hosts are unaffected: the tool's JSON payload is unchanged apart from a new `_card` field.
  - The renderable tool advertises the UI via `_meta` (`ui/resourceUri`, plus the nested `ui.resourceUri` form) pointing at a new `ui://proofpoint/threat-card.html` resource served as `text/html;profile=mcp-app`. The card HTML is a self-contained vite single-file bundle embedded at build time (`src/generated/threat-card-html.ts`, committed), so plain `npm run build` and CI never need vite. The server now declares the `resources` capability and answers `resources/list` / `resources/read` (`src/resources.ts`).
  - The card is neutral by default (system fonts, no vendor identity, no external fetches) and brandable via `window.__BRAND__` injection or `MCP_BRAND_*` env vars (`MCP_BRAND_NAME`, `MCP_BRAND_LOGO_URL`, `MCP_BRAND_PRIMARY_COLOR`, `MCP_BRAND_ACCENT_COLOR`, `MCP_BRAND_BG`, `MCP_BRAND_TEXT`): at serve time the server replaces the card's BRAND_INJECT marker with an inline, `<`-escaped `window.__BRAND__` script, so self-hosters can theme the card without rebuilding. No brand configured = HTML served unchanged.
  - The card payload builder is best-effort: a payload that doesn't look like a threat summary (or a builder failure) drops the card without affecting the tool result. 16 new contract tests in `src/__tests__/mcp-apps.test.ts` pin the `_meta` advertisement, the `ui://` resource wire shape, the neutral-default/brand-injection behavior, and the card normalization.
- Lazy-loading meta-tools mode (`LAZY_LOADING=true` env var) as alternative to decision-tree navigation
- `proofpoint_list_categories` meta-tool to discover all 11 domain categories
- `proofpoint_list_category_tools` meta-tool to lazy-load full tool schemas per category
- `proofpoint_execute_tool` meta-tool to execute any domain tool by name
- `proofpoint_router` meta-tool for intent-based tool discovery via keyword matching
- `src/utils/categories.ts` with tool category definitions and intent routing

## [1.0.0] - 2026-03-10

### Added

- Initial scaffolding of the Proofpoint MCP server
- Decision tree navigation with 11 domains
- **TAP (Targeted Attack Protection)** domain: get all threats, messages delivered/blocked, clicks permitted/blocked via SIEM API
- **Quarantine** domain: list, search, release, and delete quarantined messages
- **Threat Intelligence** domain: get campaigns, threat details, threat families, and IOCs
- **DLP** domain: list DLP incidents, get incident details, list encrypted messages
- **People** domain: Very Attacked People (VAP) reports, top clickers, user risk scores
- **Forensics** domain: get threat/campaign forensics, search messages, auto-pull (search & destroy)
- **Smart Search** domain: message tracing, message details, email headers
- **Policy** domain: list policies, get policy details, list routing rules
- **URL Defense** domain: decode Proofpoint-rewritten URLs, analyze URLs for threats
- **Events** domain: list detection events, get event details, detection statistics
- **Reports** domain: org summary, threat summary, mail flow, executive summary
- HTTP Basic Auth credential management (service principal + secret)
- Dual transport support (stdio + HTTP streaming)
- Gateway auth mode for hosted deployments
- Elicitation support for interactive user input
- Structured stderr-only logging
- Health check endpoint for HTTP transport
