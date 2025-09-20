{
  "name": "sourcegraph-mcp-server",
  "version": "1.4.2",
  "scripts": {
    "build": "tsc",
    "start": "node dist/http-streamable-server.js",
    "start:sse": "node dist/http-server.js",
    "start:streamable": "node dist/http-streamable-server.js",
    "start:mcp": "node dist/http-server.js",
    "start:stdio": "node dist/stdio-server.js",
    "start:dev": "ts-node src/http-server.ts",
    "debug-server": "node scripts/debug-server.js",
    "test-search": "node scripts/test-search.js"
  },
  "description": "A Model Context Protocol (MCP) server that connects AI assistants to Sourcegraph code search with natural language capabilities",
  "keywords": [
    "sourcegraph",
    "mcp",
    "ai",
    "code-search",
    "claude",
    "assistant"
  ],
  "author": "Madhukar Kumar",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/madhukarkumar/sg-ts-mcp-server.git"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.9.0",
    "axios": "^1.3.0",
    "cors": "^2.8.5",
    "dotenv": "^16.0.0",
    "express": "^4.18.2",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/express": "^4.17.14",
    "@types/node": "^18.0.0",
    "typescript": "^4.9.0"
  },
  "bin": {
    "sourcegraph-mcp-server": "dist/stdio-server.js"
  }
}