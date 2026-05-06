# TheHive MCP Server

A custom MCP server for accessing TheHive via REST API, designed to connect with n8n MCP client.

## Features

- Full access to TheHive REST API
- MCP protocol over HTTP
- Docker containerized
- Tools for alerts, cases, tasks, observables, etc.

## Prerequisites

- Docker and Docker Compose
- TheHive instance access

## Running

1. Clone or copy this project
2. Update `.env` with your TheHive credentials
3. Run `docker compose up --build`

## Connecting to n8n

Configure n8n MCP client with:
- URL: http://localhost:8080/mcp
- Protocol: MCP 1.0

## Available Tools

- `get-alerts`: Retrieve all alerts
- `create-alert`: Create a new alert
- `get-cases`: Retrieve all cases
- `create-case`: Create a new case
- `get-tasks`: Get tasks for a case
- `create-task`: Create a task for a case
- `get-observables`: Get observables for a case
- `create-observable`: Create an observable for a case
- `get-logs`: Get logs for a case
- `create-log`: Create a log for a case
- `get-attachments`: Get attachments for a case

## API Reference

Based on TheHive API: https://docs.thehive-project.org/thehive/api/