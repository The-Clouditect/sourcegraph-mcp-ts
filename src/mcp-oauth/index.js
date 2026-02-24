import { AuthorizationCode } from 'simple-oauth2';
import crypto from 'crypto';
import express from 'express';

/**
 * MCPOAuth - Full OAuth 2.1 flow implementation with PKCE
 * Mounts complete OAuth stack at subdomain root
 */
export class MCPOAuth {
  constructor({ redis, config }) {
    // Validate required parameters
    if (!redis) throw new Error('Redis client required');
    if (!config) throw new Error('Config object required');
    if (!config.service_name) throw new Error('config.service_name required');
    if (!config.github_id) throw new Error('config.github_id required');
    if (!config.github_secret) throw new Error('config.github_secret required');
    if (!config.public_url) throw new Error('config.public_url required (full subdomain URL)');
    
    this.redis = redis;
    this.config = config;
    this.service = config.service_name;
    this.publicUrl = config.public_url;
    this.initialized = false;
  }
  
  async initialize() {
    if (this.initialized) {
      throw new Error('OAuth already initialized');
    }
    
    // Setup logger
    const debugEnabled = process.env.OAUTH_DEBUG === 'true';
    this.logger = this.config.logger || {
      log: (msg) => console.log(msg),
      debug: debugEnabled ? (msg) => console.log(`[DEBUG] ${msg}`) : () => {},
      error: (msg) => console.error(msg)
    };
    
    // Configure TTLs - require all values
    if (!process.env.OAUTH_TTL_AUTH_REQUEST) throw new Error('OAUTH_TTL_AUTH_REQUEST required');
    if (!process.env.OAUTH_TTL_AUTH_CODE) throw new Error('OAUTH_TTL_AUTH_CODE required');
    if (!process.env.OAUTH_TTL_BEARER_TOKEN) throw new Error('OAUTH_TTL_BEARER_TOKEN required');
    if (!process.env.OAUTH_TTL_CLIENT) throw new Error('OAUTH_TTL_CLIENT required');
    
    this.ttl = {
      auth_request: parseInt(process.env.OAUTH_TTL_AUTH_REQUEST),
      auth_code: parseInt(process.env.OAUTH_TTL_AUTH_CODE),
      bearer_token: parseInt(process.env.OAUTH_TTL_BEARER_TOKEN),
      client: parseInt(process.env.OAUTH_TTL_CLIENT)
    };
    
    // Validate TTLs are numbers
    if (isNaN(this.ttl.auth_request)) throw new Error('OAUTH_TTL_AUTH_REQUEST must be a number');
    if (isNaN(this.ttl.auth_code)) throw new Error('OAUTH_TTL_AUTH_CODE must be a number');
    if (isNaN(this.ttl.bearer_token)) throw new Error('OAUTH_TTL_BEARER_TOKEN must be a number');
    if (isNaN(this.ttl.client)) throw new Error('OAUTH_TTL_CLIENT must be a number');
    
    // Configure other settings - require all values
    if (!process.env.OAUTH_GITHUB_SCOPE) throw new Error('OAUTH_GITHUB_SCOPE required');
    if (!process.env.OAUTH_REDIS_PREFIX) throw new Error('OAUTH_REDIS_PREFIX required');
    
    this.githubScope = process.env.OAUTH_GITHUB_SCOPE;
    this.redisPrefix = process.env.OAUTH_REDIS_PREFIX;
    
    // Initialize GitHub OAuth client
    this.githubClient = new AuthorizationCode({
      client: {
        id: this.config.github_id,
        secret: this.config.github_secret
      },
      auth: {
        tokenHost: 'https://github.com',
        tokenPath: '/login/oauth/access_token',
        authorizePath: '/login/oauth/authorize'
      }
    });
    
    // Register service if not disabled
    if (this.config.auto_register !== false) {
      await this.registerService();
    }
    
    this.initialized = true;
    this.logger.log(`OAuth: Service ${this.service} initialized at ${this.publicUrl}`);
    return this;
  }
  
  async registerService() {
    try {
      await this.redis.hset(`${this.redisPrefix}:services`, this.service, JSON.stringify({
        url: this.publicUrl,
        status: 'active',
        registered_at: Date.now()
      }));
      this.logger.debug(`OAuth: Service ${this.service} registered`);
    } catch (error) {
      throw new Error(`Failed to register service ${this.service}: ${error.message}`);
    }
  }
  
  // Helper for safe JSON parsing in route handlers
  safeJsonParse(str, fallback = null) {
    try { return JSON.parse(str); }
    catch { return fallback; }
  }
  
  setupRoutes(app) {
    if (!this.initialized) {
      throw new Error('OAuth not initialized. Call initialize() first');
    }
    
    this.logger.debug(`OAuth: Setting up routes at root for ${this.service}`);
    
    // Parse JSON body for token and register endpoints
    app.use('/token', express.json());
    app.use('/token', express.urlencoded({ extended: false }));
    app.use('/register', express.json());
    
    // OAuth 2.0 Authorization Server Metadata (RFC 8414)
    app.get('/.well-known/oauth-authorization-server', (req, res) => {
      res.json({
        issuer: this.publicUrl,
        authorization_endpoint: `${this.publicUrl}/authorize`,
        token_endpoint: `${this.publicUrl}/token`,
        registration_endpoint: `${this.publicUrl}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"]
      });
    });
    
    // Protected Resource Metadata (RFC 9728)
    app.get('/.well-known/oauth-protected-resource', (req, res) => {
      res.json({
        resource: this.publicUrl,
        authorization_servers: [this.publicUrl]
      });
    });
    
    // Dynamic client registration (RFC 7591)
    app.post('/register', async (req, res) => {
      this.logger.debug(`OAuth Register: Request from ${req.ip}`);
      
      try {
        // Generate client credentials
        const clientId = crypto.randomUUID();
        const clientSecret = crypto.randomBytes(32).toString('hex');
        
        // Store client in Redis
        await this.redis.set(
          `${this.redisPrefix}:${this.service}:clients:${clientId}`,
          JSON.stringify({
            client_secret: clientSecret,
            redirect_uris: req.body.redirect_uris || [],
            created_at: Date.now()
          }),
          'EX', this.ttl.client
        );
        
        this.logger.debug(`OAuth Register: Client registered: ${clientId}`);
        
        res.json({
          client_id: clientId,
          client_secret: clientSecret,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          redirect_uris: req.body.redirect_uris || [],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "client_secret_post"
        });
      } catch (error) {
        this.logger.error(`OAuth Register: Registration failed: ${error.message}`);
        res.status(500).json({
          error: 'server_error',
          error_description: 'Client registration failed'
        });
      }
    });
    
    // Authorization endpoint with PKCE
    app.get('/authorize', async (req, res) => {
      this.logger.debug(`OAuth Auth: Request: ${JSON.stringify(req.query)}`);
      const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;
      
      // Validate response_type
      if (!response_type || response_type !== 'code') {
        return res.status(400).json({
          error: 'unsupported_response_type',
          error_description: 'response_type must be code'
        });
      }
      
      // PKCE mandatory (OAuth 2.1)
      if (!code_challenge) {
        return res.status(400).json({ 
          error: 'invalid_request',
          error_description: 'code_challenge required (PKCE mandatory in OAuth 2.1)'
        });
      }
      
      // S256 only
      if (code_challenge_method && code_challenge_method !== 'S256') {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Only S256 code_challenge_method supported'
        });
      }
      
      // Validate client
      if (!client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'client_id required'
        });
      }
      
      const clientDataStr = await this.redis.get(`${this.redisPrefix}:${this.service}:clients:${client_id}`);
      if (!clientDataStr) {
        this.logger.debug(`OAuth Auth: Unknown client_id: ${client_id}`);
        return res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client not registered'
        });
      }
      
      // Validate redirect_uri if provided
      if (redirect_uri) {
        const clientData = this.safeJsonParse(clientDataStr);
        if (!clientData) {
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Invalid client data'
          });
        }
        
        if (clientData.redirect_uris.length > 0 && !clientData.redirect_uris.includes(redirect_uri)) {
          return res.status(400).json({
            error: 'invalid_request',
            error_description: 'Redirect URI not registered for this client'
          });
        }
      }
      
      // Store authorization request
      const authReqId = crypto.randomUUID();
      await this.redis.set(
        `${this.redisPrefix}:${this.service}:authreq:${authReqId}`,
        JSON.stringify({
          client_id,
          redirect_uri,
          code_challenge,
          state,
          created_at: Date.now()
        }),
        'EX', this.ttl.auth_request
      );
      
      // Redirect to GitHub
      const githubUrl = this.githubClient.authorizeURL({
        redirect_uri: `${this.publicUrl}/callback`,
        scope: this.githubScope,
        state: authReqId
      });
      
      res.redirect(githubUrl);
    });
    
    // GitHub callback handler
    app.get('/callback', async (req, res) => {
      const { code, state: authReqId } = req.query;
      
      if (!code || !authReqId) {
        return res.status(400).json({ 
          error: 'invalid_request',
          error_description: 'Missing code or state parameter'
        });
      }
      
      // Retrieve auth request
      const authReqStr = await this.redis.get(`${this.redisPrefix}:${this.service}:authreq:${authReqId}`);
      if (!authReqStr) {
        return res.status(400).json({ 
          error: 'invalid_request',
          error_description: 'Invalid or expired authorization request'
        });
      }
      
      const authReq = this.safeJsonParse(authReqStr);
      if (!authReq) {
        return res.status(500).json({ 
          error: 'server_error',
          error_description: 'Invalid authorization request data'
        });
      }
      
      await this.redis.del(`${this.redisPrefix}:${this.service}:authreq:${authReqId}`);
      
      try {
        // Exchange GitHub code for token
        const tokenResult = await this.githubClient.getToken({
          code: code,
          redirect_uri: `${this.publicUrl}/callback`
        });
        
        if (!tokenResult.token?.access_token) {
          this.logger.error('OAuth Callback: GitHub token exchange failed');
          return res.status(502).json({
            error: 'server_error',
            error_description: 'GitHub authentication failed'
          });
        }
        
        // Generate our authorization code
        const ourCode = crypto.randomUUID();
        
        // Store with PKCE challenge
        await this.redis.set(
          `${this.redisPrefix}:${this.service}:authcode:${ourCode}`,
          JSON.stringify({
            github_token: tokenResult.token.access_token,
            code_challenge: authReq.code_challenge,
            client_id: authReq.client_id,
            created_at: Date.now()
          }),
          'EX', this.ttl.auth_code
        );
        
        // Redirect to client
        const redirectUrl = new URL(authReq.redirect_uri);
        redirectUrl.searchParams.set('code', ourCode);
        if (authReq.state) {
          redirectUrl.searchParams.set('state', authReq.state);
        }
        
        res.redirect(redirectUrl.toString());
      } catch (error) {
        this.logger.error(`OAuth Callback: Error: ${error.message}`);
        res.status(500).json({ 
          error: 'server_error',
          error_description: 'OAuth callback processing failed'
        });
      }
    });
    
    // Token endpoint with PKCE validation
    app.post('/token', async (req, res) => {
      const { grant_type, code, client_id, client_secret, code_verifier } = req.body;
      
      // Validate grant type
      if (grant_type !== 'authorization_code') {
        return res.status(400).json({ 
          error: 'unsupported_grant_type',
          error_description: 'Only authorization_code grant type supported'
        });
      }
      
      // Validate required parameters
      if (!code) {
        return res.status(400).json({ 
          error: 'invalid_request',
          error_description: 'Authorization code required'
        });
      }
      
      if (!client_id) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'client_id required'
        });
      }
      
      if (!code_verifier) {
        return res.status(400).json({ 
          error: 'invalid_request',
          error_description: 'code_verifier required for PKCE'
        });
      }
      
      // Retrieve and validate auth code
      const authDataStr = await this.redis.get(`${this.redisPrefix}:${this.service}:authcode:${code}`);
      if (!authDataStr) {
        return res.status(400).json({ 
          error: 'invalid_grant',
          error_description: 'Authorization code invalid or expired'
        });
      }
      
      const authData = this.safeJsonParse(authDataStr);
      if (!authData) {
        return res.status(500).json({ 
          error: 'server_error',
          error_description: 'Invalid authorization data'
        });
      }
      
      await this.redis.del(`${this.redisPrefix}:${this.service}:authcode:${code}`); // Single use
      
      // Validate client match
      if (client_id !== authData.client_id) {
        this.logger.debug(`OAuth Token: Client mismatch: ${client_id} != ${authData.client_id}`);
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Authorization code was issued to different client'
        });
      }
      
      // PKCE validation
      const hash = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (hash !== authData.code_challenge) {
        return res.status(400).json({ 
          error: 'invalid_grant',
          error_description: 'PKCE validation failed'
        });
      }
      
      // Optional client secret validation
      if (client_secret) {
        const clientDataStr = await this.redis.get(`${this.redisPrefix}:${this.service}:clients:${client_id}`);
        if (!clientDataStr) {
          return res.status(400).json({
            error: 'invalid_client',
            error_description: 'Client registration expired'
          });
        }
        
        const clientData = this.safeJsonParse(clientDataStr);
        if (!clientData) {
          return res.status(500).json({
            error: 'server_error',
            error_description: 'Invalid client data'
          });
        }
        
        if (clientData.client_secret !== client_secret) {
          return res.status(400).json({
            error: 'invalid_client',
            error_description: 'Client authentication failed'
          });
        }
      }
      
      // Issue bearer token
      const bearerToken = crypto.randomUUID();
      
      await this.redis.set(
        `${this.redisPrefix}:${this.service}:token:${bearerToken}`,
        authData.github_token,
        'EX', this.ttl.bearer_token
      );
      
      res.json({
        access_token: bearerToken,
        token_type: 'Bearer',
        expires_in: this.ttl.bearer_token
      });
    });
    
    this.logger.log(`OAuth: Routes mounted for ${this.service}`);
  }
  
  async cleanup() {
    try {
      // Delete all keys for this service
      const pattern = `${this.redisPrefix}:${this.service}:*`;
      const keys = await this.redis.keys(pattern);
      
      if (keys.length > 0) {
        await this.redis.del(...keys);
        this.logger.debug(`OAuth: Deleted ${keys.length} keys for ${this.service}`);
      }
      
      // Unregister service
      await this.redis.hdel(`${this.redisPrefix}:services`, this.service);
      this.logger.log(`OAuth: Service ${this.service} cleanup complete`);
    } catch (error) {
      this.logger.error(`OAuth cleanup failed for ${this.service}: ${error.message}`);
      // Don't throw - we're shutting down
    }
  }
}

/**
 * BearerValidator - Token validation middleware
 * Protects MCP endpoints with bearer token auth
 */
export class BearerValidator {
  constructor({ redis, config }) {
    if (!redis) throw new Error('Redis client required');
    if (!config) throw new Error('Config object required');
    if (!config.service_name) throw new Error('config.service_name required');
    if (!config.public_url) throw new Error('config.public_url required');
    
    this.redis = redis;
    this.config = config;
    this.service = config.service_name;
    this.publicUrl = config.public_url;
    this.initialized = false;
    
    // Bind middleware method
    this.requireAuth = this.requireAuth.bind(this);
  }
  
  async initialize() {
    if (this.initialized) {
      throw new Error('BearerValidator already initialized');
    }
    
    // Setup logger
    const debugEnabled = process.env.OAUTH_DEBUG === 'true';
    this.logger = this.config.logger || {
      log: (msg) => console.log(msg),
      debug: debugEnabled ? (msg) => console.log(`[DEBUG] ${msg}`) : () => {},
      error: (msg) => console.error(msg)
    };
    
    // Configure settings - require all values
    if (!process.env.OAUTH_REDIS_PREFIX) throw new Error('OAUTH_REDIS_PREFIX required');
    if (!process.env.OAUTH_INTERNAL_NETWORKS) throw new Error('OAUTH_INTERNAL_NETWORKS required');
    
    this.redisPrefix = process.env.OAUTH_REDIS_PREFIX;
    this.internalNetworks = process.env.OAUTH_INTERNAL_NETWORKS
      .split(',')
      .map(n => n.trim());
    
    this.initialized = true;
    this.logger.log(`BearerValidator: Initialized for ${this.service}`);
    return this;
  }
  
  async requireAuth(req, res, next) {
    if (!this.initialized) {
      return res.status(503).json({
        jsonrpc: '2.0',
        error: { 
          code: -32000, 
          message: 'Service not initialized' 
        },
        id: null
      });
    }
    
    // Internal network bypass
    const clientIp = req.ip || req.connection.remoteAddress;
    const isInternal = this.internalNetworks.some(network => 
      clientIp === network || clientIp?.startsWith(network)
    );
    
    if (isInternal) {
      req.isInternalRequest = true;
      this.logger.debug(`BearerValidator: Internal request from ${clientIp} - bypassing auth`);
      return next();
    }
    
    // Extract bearer token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      this.logger.debug(`BearerValidator: Missing or invalid authorization header`);
      // MCP-compliant 401 response
      return res.status(401)
        .set('WWW-Authenticate', 
             `Bearer resource_metadata="${this.publicUrl}/.well-known/oauth-protected-resource"`)
        .json({
          jsonrpc: '2.0',
          error: { 
            code: -32000, 
            message: 'Authentication required' 
          },
          id: null
        });
    }
    
    const bearerToken = authHeader.substring(7);
    
    // Validate token
    try {
      const githubToken = await this.redis.get(`${this.redisPrefix}:${this.service}:token:${bearerToken}`);
      if (!githubToken) {
        this.logger.debug(`BearerValidator: Invalid or expired token`);
        return res.status(401).json({
          jsonrpc: '2.0',
          error: { 
            code: -32000, 
            message: 'Invalid or expired token' 
          },
          id: null
        });
      }
      
      // Add tokens to request
      req.githubToken = githubToken;
      req.bearerToken = bearerToken;
      this.logger.debug(`BearerValidator: Token validated successfully`);
      next();
    } catch (error) {
      this.logger.error(`BearerValidator: Token validation error: ${error.message}`);
      return res.status(503).json({
        jsonrpc: '2.0',
        error: { 
          code: -32000, 
          message: 'Token validation temporarily unavailable' 
        },
        id: null
      });
    }
  }
  
  async cleanup() {
    try {
      // BearerValidator doesn't own any Redis keys
      // Cleanup is handled by MCPOAuth
      this.logger.log(`BearerValidator: Cleanup complete for ${this.service}`);
    } catch (error) {
      this.logger.error(`BearerValidator cleanup failed: ${error.message}`);
      // Don't throw - we're shutting down
    }
  }
}