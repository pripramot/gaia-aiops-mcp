import 'dotenv/config';
import express, {
  type Request,
  type Response,
  type NextFunction,
} from 'express';
import helmet       from 'helmet';
import cors         from 'cors';
import compression  from 'compression';
import rateLimit    from 'express-rate-limit';
import { McpServer }          from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';

import { logger }         from './utils/logger.js';
import { pool }           from './config/database.js';
import { authRouter }     from './routes/auth.js';
import { casesRouter }    from './routes/cases.js';
import { evidenceRouter } from './routes/evidence.js';
import { chronosRouter }  from './routes/chronos.js';
import { mcpRouter, registerMcpTools } from './routes/mcp.js';
import { auditMiddleware } from './middleware/audit.js';

const app  = express();
const PORT = Number(process.env.PORT ?? 3890);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(
  helmet({
    // Allow SSE responses (chunked transfer)
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'"],
        styleSrc:   ["'self'"],
        connectSrc: ["'self'"],
      },
    },
  }),
);

// ── CORS — restrict to known origins ─────────────────────────────────────────
const allowedOrigins = (
  process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173'
).split(',').map((o) => o.trim());

app.use(
  cors({
    origin(origin, callback) {
      // Allow requests with no origin in development (curl, local MCP client)
      if (!origin && process.env.NODE_ENV === 'development') {
        return callback(null, true);
      }
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error(`CORS: origin "${origin}" not allowed`));
    },
    credentials: true,
  }),
);

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use(
  '/api/auth',
  rateLimit({
    windowMs:       15 * 60 * 1000,
    max:            20,
    standardHeaders: true,
    legacyHeaders:  false,
    message: { error: 'Too many auth requests — try again later.' },
  }),
);

app.use(
  '/api',
  rateLimit({
    windowMs:       60 * 1000,
    max:            300,
    standardHeaders: true,
    legacyHeaders:  false,
  }),
);

// ── Body parsing + compression ───────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(compression());

// ── Audit middleware (fire-and-forget for every /api response) ────────────────
app.use('/api', auditMiddleware as never);

// ── REST routes ───────────────────────────────────────────────────────────────
app.use('/api/auth',     authRouter);
app.use('/api/cases',    casesRouter);
app.use('/api/evidence', evidenceRouter);
app.use('/api/chronos',  chronosRouter);
app.use('/api/mcp',      mcpRouter);

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', async (_req: Request, res: Response) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status:    'ok',
      db:        'connected',
      service:   'gtsalpha-forensics-mcp',
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

// ── MCP SSE endpoint ──────────────────────────────────────────────────────────
// Active transports keyed by session UUID
const activeSessions = new Map<string, SSEServerTransport>();

app.get('/mcp', async (req: Request, res: Response) => {
  // Accept token via Authorization header or ?token= query param
  const token =
    (req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined) ??
    (req.query['token'] as string | undefined);

  if (!token) {
    res.status(401).json({ error: 'MCP session token required' });
    return;
  }

  // Create a fresh McpServer per SSE connection
  const mcpServer = new McpServer({
    name:    'gtsalpha-forensics',
    version: '1.0.0',
  });

  registerMcpTools(mcpServer, token);

  // SSEServerTransport expects the path where the client will POST messages
  const transport = new SSEServerTransport('/mcp/message', res);
  const sessionId = crypto.randomUUID();

  activeSessions.set(sessionId, transport);
  res.setHeader('X-MCP-Session-Id', sessionId);

  transport.onclose = () => {
    activeSessions.delete(sessionId);
    logger.info('MCP session closed', { sessionId });
  };

  await mcpServer.connect(transport);
  logger.info('MCP session opened', { sessionId, token: token.slice(0, 8) + '…' });
});

// ── MCP message relay ─────────────────────────────────────────────────────────
app.post('/mcp/message', async (req: Request, res: Response) => {
  const sessionId = req.headers['x-mcp-session-id'] as string | undefined;

  if (!sessionId) {
    res.status(400).json({ error: 'X-MCP-Session-Id header required' });
    return;
  }

  const transport = activeSessions.get(sessionId);
  if (!transport) {
    res.status(404).json({ error: 'MCP session not found or expired' });
    return;
  }

  await transport.handlePostMessage(req, res);
});

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' });
});

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error('Unhandled error', { message: err.message, stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`GTSAlpha MCP Server listening on port ${PORT}`);
  logger.info(`REST API  : http://localhost:${PORT}/api`);
  logger.info(`MCP SSE   : http://localhost:${PORT}/mcp`);
  logger.info(`Health    : http://localhost:${PORT}/health`);
  logger.info(`Production: https://nfc.gtsalphamcp.com`);
});

export default app;
