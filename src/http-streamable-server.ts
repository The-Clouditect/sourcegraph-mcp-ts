#!/usr/bin/env node

import express from "express";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "./mcp-server";
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  console.log('Starting Sourcegraph MCP Server (StreamableHTTP)...');
  console.log(`SOURCEGRAPH_URL: ${process.env.SOURCEGRAPH_URL ? 'Set' : 'NOT SET'}`);
  console.log(`SOURCEGRAPH_TOKEN: ${process.env.SOURCEGRAPH_TOKEN ? 'Set (redacted)' : 'NOT SET'}`);

  const server = createServer();
  const app = express();
  const port = process.env.MCP_STREAMABLE_PORT || 3003;
  
  // CORS for Claude.ai
  const ADDITIONAL_ORIGINS = process.env.CORS_ALLOWED_ORIGINS 
    ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

  app.use(cors({
    origin: ['https://claude.ai', ...ADDITIONAL_ORIGINS],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id']
  }));
  
  app.use(express.json());
  
  // Session management
  const transports = {};
  
  // Helper to check initialize request
  function isInitializeRequest(body) {
    return body?.method === 'initialize';
  }
  
  // MCP endpoint with session management
  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    let transport;
    
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