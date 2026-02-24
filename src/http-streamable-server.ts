#!/usr/bin/env node

import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "./mcp-server.js";
import crypto from 'crypto';
import dotenv from 'dotenv';
import Redis from 'ioredis';
import { MCPOAuth, BearerValidator } from './mcp-oauth/index.js';

dotenv.config();

const SERVICE_NAME = 'mcp_code';
const DEBUG = process.env.DEBUG === 'true';

async function main() {
  console.log('Starting Sourcegraph MCP Server (StreamableHTTP with OAuth)...');
  console.log(`SOURCEGRAPH_URL: ${process.env.SOURCEGRAPH_URL ? 'Set' : 'NOT SET'}`);
  console.log(`SOURCEGRAPH_TOKEN: ${process.env.SOURCEGRAPH_TOKEN ? 'Set (redacted)' : 'NOT SET'}`);

  const app = express();
  app.set('trust proxy', true);
  const port = parseInt(process.env.MCP_STREAMABLE_PORT || '3003');

  if (!process.env.REDIS_HOST || !process.env.REDIS_PORT) {
    throw new Error('REDIS_HOST and REDIS_PORT required');
  }
  
  // Initialize Redis with mcp-docs pattern
  const redis = new Redis({
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT)
  });
  
  await redis.ping();
  if (DEBUG) console.log('Redis connected');
  
  // Initialize OAuth components
  const oauth = await new MCPOAuth({
    redis: redis,
    config: {
      service_name: SERVICE_NAME,
      github_id: process.env.GITHUB_CODE_CLIENT_ID!,
      github_secret: process.env.GITHUB_CODE_CLIENT_SECRET!,
      public_url: process.env.CODE_PUBLIC_URL!,
      auto_register: true
    }
  }).initialize();
  
  const bearerValidator = await new BearerValidator({
    redis: redis,
    config: {
      service_name: SERVICE_NAME,
      public_url: process.env.CODE_PUBLIC_URL!
    }
  }).initialize();
  
  if (DEBUG) console.log('OAuth components initialized');
  
  // CORS configuration
  const ADDITIONAL_ORIGINS = process.env.CORS_ALLOWED_ORIGINS 
    ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://claude.ai', ...ADDITIONAL_ORIGINS];
    
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, mcp-session-id');
    
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });
  
  app.use(express.json());
  
  // Setup OAuth routes at root
  oauth.setupRoutes(app);
  
  // Session management for MCP
  const transports: Record<string, StreamableHTTPServerTransport> = {};
  const servers: Record<string, ReturnType<typeof createServer>> = {};
  
  function isInitializeRequest(body: any): boolean {
    return body?.method === 'initialize';
  }
  
  // Protected MCP endpoint
  app.post('/mcp', 
    bearerValidator.requireAuth,
    async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      let transport: StreamableHTTPServerTransport;
      
      if (!sessionId && isInitializeRequest(req.body)) {
        const newSessionId = crypto.randomUUID();
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => newSessionId,
        });
        const server = createServer();
        transports[newSessionId] = transport;
        servers[newSessionId] = server;
        await server.connect(transport);
        transport.onclose = () => {
          delete transports[newSessionId];
          delete servers[newSessionId];
          if (DEBUG) console.log(`Session cleaned up: ${newSessionId}`);
        });
        if (DEBUG) console.log(`Session created: ${newSessionId}`);
      } else if (sessionId && transports[sessionId]) {
        transport = transports[sessionId];
      } else {
        return res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Invalid session' },
          id: null,
        });
      }
      
      await transport.handleRequest(req, res, req.body);
    }
  );
  
  // Health check
  app.get('/health', (req, res) => {
    res.json({
      name: "Sourcegraph MCP Server",
      version: "1.0.0",
      transport: "StreamableHTTP",
      oauth: "enabled",
      status: "running",
      tools: ["echo", "search-code", "search-commits", "search-diffs", "debug"]
    });
  });
  
  app.listen(port, '0.0.0.0', () => {
    console.log(`StreamableHTTP OAuth server running on port ${port}`);
    console.log(`OAuth endpoints active at ${process.env.CODE_PUBLIC_URL}`);
    console.log(`- GET /.well-known/oauth-authorization-server`);
    console.log(`- GET /.well-known/oauth-protected-resource`);
    console.log(`- GET /authorize`);
    console.log(`- GET /callback`);
    console.log(`- POST /token`);
    console.log(`- POST /register`);
    console.log(`- POST /mcp (protected)`);
    console.log(`- GET /health`);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', async () => {
    await oauth.cleanup();
    await bearerValidator.cleanup();
    await redis.quit();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});