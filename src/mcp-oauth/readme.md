# MCP OAuth Package

OAuth 2.1 authorization layer for MCP (Model Context Protocol) servers with GitHub integration.

## Design Overview

This package provides two core components:

1. **MCPOAuth** - Full OAuth 2.1 authorization server implementation
   - PKCE-enforced authorization flow
   - GitHub OAuth backend for identity verification
   - Bearer token issuance for API access
   - RFC-compliant discovery endpoints

2. **BearerValidator** - Express middleware for token validation
   - Validates bearer tokens on protected endpoints
   - Internal network bypass for Docker networking
   - MCP-compliant error responses

## Architecture

```
Client (Claude.ai) ? OAuth Server ? GitHub OAuth ? Bearer Token ? MCP Server
```

Each MCP service runs as an independent subdomain with its own OAuth flow:
- Service registration in Redis
- Token storage with configurable TTLs
- Service-namespaced keys for isolation

## Use Case

Secure MCP servers deployed on public URLs by requiring GitHub authentication:

1. Claude.ai connects to MCP server subdomain
2. OAuth flow redirects to GitHub for authentication
3. Server issues bearer token after successful auth
4. All subsequent MCP requests include bearer token
5. Internal Docker services bypass auth via network detection

## Requirements

- Redis client (injected by consuming application, not included)
- GitHub OAuth application per service
- Express.js server framework
- All configuration via environment variables (no defaults)

## Dependencies

This package requires the consuming application to provide:
- Redis client instance (ioredis or compatible)
- Express app instance for route mounting

## Configuration

See integration checklist for required environment variables and setup instructions.

## Status

Pre-production - pending integration testing with mcp-docs server.