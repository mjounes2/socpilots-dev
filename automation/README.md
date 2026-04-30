# automation/

This folder is used by the unified stack (../docker-compose.yml) for n8n persistent data.

The `n8n_data/` volume is created automatically by Docker when you run:

    docker compose up -d

from the ROOT directory (one level up from here).

## n8n URLs (on the unified stack)

- Dashboard: http://YOUR_SERVER_IP:5678
- Webhook base: http://YOUR_SERVER_IP:5678/webhook/...

## Internal service URLs (use inside n8n workflows)

| Service       | Internal URL                  |
|---------------|-------------------------------|
| MCP Wazuh     | http://mcp-wazuh:3001         |
| MCP TheHive   | http://thehive-mcp:8080       |
| SOCPilots API | http://webapp:3000/api/...    |
