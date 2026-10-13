# Proofpoint MCP Server

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

A Model Context Protocol (MCP) server for Proofpoint TAP and Essentials APIs. Enables AI assistants to investigate threats, trace emails, manage quarantine, access threat intelligence, and perform URL defense operations.

This is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that connects Claude (or any MCP-compatible AI) to your Proofpoint environment.

> **Part of the [MSP Claude Plugins](https://github.com/WYRE-AI) ecosystem** — a growing suite of AI integrations for the MSP stack. Built by MSPs, for MSPs.

## Installation

```bash
npm install @wyre-ai/proofpoint-mcp
```

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. The stdio transport reads `PROOFPOINT_*` and does not use HTTP service-to-service auth.

| Variable | Required | Description |
|----------|----------|-------------|
| `PROOFPOINT_SERVICE_PRINCIPAL` | For stdio and `AUTH_MODE=env` | Proofpoint TAP service principal |
| `PROOFPOINT_SERVICE_SECRET` | For stdio and `AUTH_MODE=env` | Proofpoint TAP service secret |
| `PROOFPOINT_BASE_URL` | No | API host. Defaults to `https://tap-api-v2.proofpoint.com`. Not a credential. |
| `MCP_TRANSPORT` | No | `stdio` (default) or `http` |
| `AUTH_MODE` | No | `gateway` (Docker image and Compose) or `env`. Gateway mode requires `X-Proofpoint-Service-Principal` and `X-Proofpoint-Service-Secret` on each `/mcp` request and never falls back to `PROOFPOINT_*`. `env` uses those variables only after S2S auth succeeds. Unset means `env` (stdio and single-tenant HTTP). |
| `CONDUIT_S2S_SECRET` | Yes for HTTP | Service-to-service secret. The HTTP server logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `secret`, `replace-me`, `your-s2s-secret`, and the other example values). Generate one with `openssl rand -hex 32`. Compose will not start without it. The value is never logged. |
| `MCP_ALLOW_INSECURE_DEV` | No | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A wider `MCP_HTTP_HOST` (including `0.0.0.0`) is ignored and the override is logged. A known placeholder secret still refuses to start. |
| `MCP_HTTP_HOST` | No | Bind address when a real `CONDUIT_S2S_SECRET` is set. Unset defaults to `127.0.0.1`. The container image and Compose set `0.0.0.0` inside the container. |
| `MCP_HTTP_PORT` | No | HTTP port. Defaults to `8080`. |

`/health` and `/healthz` stay unauthenticated and do not read credentials.

### HTTP authentication

With `MCP_TRANSPORT=http` and `CONDUIT_S2S_SECRET` set, every `/mcp` request must include `X-Gateway-S2S`. The check is `verifyS2sHeader` in [`src/s2s-verify.ts`](src/s2s-verify.ts): the header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header is HTTP 401, before vendor credentials are read.

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Proofpoint-Service-Principal` and `X-Proofpoint-Service-Secret` (`X-Proofpoint-Cluster-Url` is optional). Those headers are the only credential source for that request. A request missing either required header returns 401 and does not fall back to `PROOFPOINT_SERVICE_PRINCIPAL` / `PROOFPOINT_SERVICE_SECRET`.

## Usage

### Running with Claude Desktop

Add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "proofpoint-mcp": {
      "command": "npx",
      "args": ["@wyre-ai/proofpoint-mcp"],
      "env": {
        "PROOFPOINT_SERVICE_PRINCIPAL": "your-proofpoint-service-principal"
        "PROOFPOINT_SERVICE_SECRET": "your-proofpoint-service-secret"
      }
    }
  }
}
```

### Running with Claude Code (CLI)

```bash
claude mcp add proofpoint-mcp \
  -e PROOFPOINT_SERVICE_PRINCIPAL=your-value \
  -e PROOFPOINT_SERVICE_SECRET=your-value \
  -- npx -y @wyre-ai/proofpoint-mcp
```

### Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass a real S2S secret. In gateway mode, Proofpoint credentials arrive on each request as headers; they are not read from the environment.

```bash
docker build -t proofpoint-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  proofpoint-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset. The gateway service does not set `PROOFPOINT_SERVICE_PRINCIPAL` or `PROOFPOINT_SERVICE_SECRET` and does not use `env_file`, so a project `.env` cannot inject static vendor credentials. Compose still interpolates `CONDUIT_S2S_SECRET` from that file. It publishes `127.0.0.1:8080:8080`:

```bash
CONDUIT_S2S_SECRET="$(openssl rand -hex 32)" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `PROOFPOINT_SERVICE_PRINCIPAL` and `PROOFPOINT_SERVICE_SECRET`. It is separate from the gateway Compose service above.

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e PROOFPOINT_SERVICE_PRINCIPAL=your-value \
  -e PROOFPOINT_SERVICE_SECRET=your-value \
  -p 127.0.0.1:8080:8080 \
  proofpoint-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` and logs a warning, even if `MCP_HTTP_HOST` is `0.0.0.0`:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm start
```

## Features

### Interactive Threat Card (MCP Apps)

`proofpoint_threat_get_by_id` renders as an interactive, read-only card in
MCP Apps hosts (Claude Desktop/web) showing the threat name, status,
category, severity, and resolved actor / malware-family / campaign names;
plain-JSON behavior is unchanged in other hosts. The card is neutral by
default and brandable via `window.__BRAND__` injection or `MCP_BRAND_*` env
vars (`MCP_BRAND_NAME`, `MCP_BRAND_LOGO_URL`, `MCP_BRAND_PRIMARY_COLOR`,
`MCP_BRAND_ACCENT_COLOR`, `MCP_BRAND_BG`, `MCP_BRAND_TEXT`) — no rebuild
needed.

## Available Domains

### Dlp
Data loss prevention policies

### Events
Security event stream and SIEM export

### Forensics
Forensic analysis of threats

### People
Very Attacked People (VAP) reporting

### Policy
Email policy management

### Quarantine
Email quarantine management

### Reports
Security reports and summaries

### Smart Search
Advanced email search

### Tap
Targeted Attack Protection events and campaigns

### Threat Intel
Threat intelligence and indicators of compromise

### Url Defense
URL rewriting and click defense


## Development

```bash
# Clone the repository
git clone https://github.com/WYRE-AI/proofpoint-mcp.git
cd proofpoint-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# HTTP refuses to start until CONDUIT_S2S_SECRET is a real secret
CONDUIT_S2S_SECRET="$(openssl rand -hex 32)" MCP_TRANSPORT=http npm start

# Local HTTP only, without a service-to-service secret (always binds 127.0.0.1)
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm start
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) if present, or open an issue to discuss changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
