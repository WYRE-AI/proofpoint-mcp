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

Set the following environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `PROOFPOINT_SERVICE_PRINCIPAL` | Yes | Your Proofpoint TAP service principal |
| `PROOFPOINT_SERVICE_SECRET` | Yes | Your Proofpoint TAP service secret |
| `PROOFPOINT_BASE_URL` | No | Custom base URL (default: tap-api-v2.proofpoint.com) |
| `MCP_TRANSPORT` | No | Transport mode: stdio (default) or http |

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

```bash
docker build -t proofpoint-mcp .
docker run \
  -e PROOFPOINT_SERVICE_PRINCIPAL=your-value \
  -e PROOFPOINT_SERVICE_SECRET=your-value \
  -p 8080:8080 proofpoint-mcp
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
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) if present, or open an issue to discuss changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
