#!/usr/bin/env node

import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "./mcp-server.js";
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  console.log('Starting Sourcegraph MCP Server (StreamableHTTP)...');
  console.log(`SOURCEGRAPH_URL: ${process.env.SOURCEGRAPH_URL ? 'Set' : 'NOT SET'}`);
  console.log(`SOURCEGRAPH_TOKEN: ${process.env.SOURCEGRAPH_TOKEN ? 'Set (redacted)' : 'NOT SET'}`);

  const server = createServer();
  const app = express();
  const port = parseInt(process.env.MCP_STREAMABLE_PORT || '3003');
  
  // CORS for Claude.ai
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
  
  // Session management
  const transports: Record<string, StreamableHTTPServerTransport> = {};
  
  // Helper to check initialize request
  function isInitializeRequest(body: any): boolean {
    return body?.method === 'initialize';
  }
  
  // MCP endpoint with session management
  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;
    
    if (!sessionId && isInitializeRequest(req.body)) {
      const newSessionId = crypto.randomUUID();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
      });
      transports[newSessionId] = transport;
      await server.connect(transport);
      console.log(`Session created: ${newSessionId}`);
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
  });
  
  // Health check
  app.get('/', (req, res) => {
    res.json({
      name: "Sourcegraph MCP Server",
      version: "1.0.0",
      transport: "StreamableHTTP",
      status: "running",
      tools: ["echo", "search-code", "search-commits", "search-diffs", "debug"]
    });
  });
  
  app.listen(port, '0.0.0.0', () => {
    console.log(`StreamableHTTP server running on port ${port}`);
    console.log(`- POST /mcp for MCP requests`);
    console.log(`- GET / for health check`);
  });
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});