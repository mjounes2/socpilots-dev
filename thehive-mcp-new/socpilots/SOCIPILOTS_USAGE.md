# Socpilots MCP Server Usage Guide

This repository contains the Wazuh MCP server implementation that can be reused for future Wazuh server integrations.

## Overview

The MCP server provides:
- `/auth/token`: exchanges a long-lived MCP API key for a JWT bearer token
- `/mcp`: the Model Context Protocol endpoint for Wazuh actions
- persistent API key support via `MCP_API_KEY`
- bearer authentication for Streamable HTTP and JSON-RPC

## Repository Layout

- `compose.yml` - Docker Compose config for the MCP server
- `Dockerfile` - container image build definition
- `src/` - Python source for the MCP server
- `.env.example` - example environment configuration
- `SOCIPILOTS_USAGE.md` - this usage guide

## Prerequisites

- Docker and Docker Compose installed
- A host that can reach Wazuh manager and indexer services
- A persistent MCP API key:
  ```bash
  python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
  ```

## Setup Steps

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` to configure Wazuh connection values and authentication:
   - `MCP_API_KEY`: the long-lived Wazuh API key
   - `AUTH_SECRET_KEY`: a secure random string for signing JWTs
   - `TOKEN_LIFETIME_HOURS`: how long `/auth/token` JWTs live
   - `WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASS`
   - `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_PORT`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS`

3. Start the server using Docker Compose:
   ```bash
   docker compose up -d
   ```

4. Verify the service is healthy:
   ```bash
   docker compose logs --tail=50 | grep -E 'Loaded API key from MCP_API_KEY|Bearer token authentication enabled|healthy'
   ```

## Token Flow

### Get a JWT token

Use the persistent `MCP_API_KEY` to obtain a JWT token:

```bash
curl -X POST http://127.0.0.1:3000/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"<MCP_API_KEY>"}'
```

Response example:

```json
{
  "access_token":"<JWT>",
  "token_type":"bearer",
  "expires_in":86400
}
```

### Call `/mcp` with the JWT

```bash
curl -X POST http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer <JWT>" \
  -H 'Content-Type: application/json' \
  -d '{"id":"test","jsonrpc":"2.0","method":"ping","params":{}}'
```

### Direct long-lived API key support

The server also accepts the long-lived `MCP_API_KEY` directly as a bearer token:

```bash
curl -X POST http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer <MCP_API_KEY>" \
  -H 'Content-Type: application/json' \
  -d '{"id":"test","jsonrpc":"2.0","method":"ping","params":{}}'
```

## n8n Integration Steps

1. Create an HTTP Request node in n8n.
2. First request: obtain the JWT.
   - Method: `POST`
   - URL: `http://<MCP_HOST>:3000/auth/token`
   - Body: raw JSON
   - JSON:
     ```json
     {
       "api_key": "<MCP_API_KEY>"
     }
     ```
3. Save the response token from `access_token`.
4. Second request: call `/mcp`.
   - Method: `POST`
   - URL: `http://<MCP_HOST>:3000/mcp`
   - Headers:
     - `Authorization`: `Bearer {{$node["AuthRequest"].json["access_token"]}}`
     - `Content-Type`: `application/json`
   - Body: raw JSON
   - JSON:
     ```json
     {
       "id": "test",
       "jsonrpc": "2.0",
       "method": "ping",
       "params": {}
     }
     ```

## Repository Publication

This local repository is prepared as `socpilots` to be published to GitHub.

If you have access to GitHub from this environment, add the remote and push:

```bash
cd /home/socpilots
git remote add origin https://github.com/<your-user>/socpilots.git
git branch -m main
git push -u origin main
```

If you want to use GitHub CLI once available:

```bash
gh auth login
gh repo create <your-user>/socpilots --public --source=. --remote=origin
git push -u origin main
```

## Notes

- The server uses `AUTH_MODE=bearer` by default.
- Use `TOKEN_LIFETIME_HOURS` to extend JWT validity.
- Keep `MCP_API_KEY` and `AUTH_SECRET_KEY` secret.
- For production, use strong random secrets and secure your Docker host.
