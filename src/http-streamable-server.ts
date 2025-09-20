#!/usr/bin/env node

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { createServer } from "./mcp-server";
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

async function main() {
  console.log('Starting Sourcegraph MCP Server (HTTP)...');
  console.log(`SOURCEGRAPH_URL: ${process.env.SOURCEGRAPH_URL ? 'Set' : 'NOT SET'}`);
  console.log(`SOURCEGRAPH_TOKEN: ${process.env.SOURCEGRAPH_TOKEN ? 'Set (redacted)' : 'NOT SET'}`);

  const server = createServer();
  const app = express();
  const port = parseInt(process.env.MCP_STREAMABLE_PORT || '3003');
  
  // CORS headers for Claude.ai
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://claude.ai'];
    const additionalOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',').map(o => o.trim()) || [];
    
    if (origin && [...allowedOrigins, ...additionalOrigins].includes(origin)) {
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
  const sessions = {};
  
  // MCP endpoint
  app.post('/mcp', async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] || crypto.randomUUID();
      
      if (!sessions[sessionId]) {
        sessions[sessionId] = { server, messages: [] };
        console.log(`New session: ${sessionId}`);
      }
      
      // Process the JSON-RPC request
      const response = await server.request(req.body, {
        sessionId
      });
      
      // Send session ID back in header
      res.setHeader('mcp-session-id', sessionId);
      res.json(response);
    } catch (error) {
      console.error('MCP request error:', error);
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: error.message },
        id: req.body?.id || null
      });
    }
  });
  
  // Health check
  app.get('/', (req, res) => {
    res.json({
      name: "Sourcegraph MCP Server",
      version: "1.0.0",
      transport: "HTTP",
      status: "running",
      tools: ["echo", "search-code", "search-commits", "search-diffs", "debug"]
    });
  });
  
  app.listen(port, '0.0.0.0', () => {
    console.log(`HTTP server running on port ${port}`);
    console.log(`- POST /mcp for MCP requests`);
    console.log(`- GET / for health check`);
  });
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});