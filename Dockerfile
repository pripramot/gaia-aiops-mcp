# =============================================================================
# GTSAlpha Forensics MCP Server — Dockerfile
# Multi-stage build → minimal Alpine runtime image
# =============================================================================

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Install deps first (cache layer)
COPY package*.json ./
RUN npm ci

# Copy source & compile TypeScript
COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# ── Stage 2: Runtime (production) ────────────────────────────────────────────
FROM node:22-alpine AS runner

LABEL maintainer="GTSAlpha C.H.R.O.N.O.S. Forensics Unit"
LABEL org.opencontainers.image.title="gtsa-mcp"
LABEL org.opencontainers.image.version="1.0.0"

# Security: run as non-root
RUN addgroup -S mcp && adduser -S mcp -G mcp

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3890

# Copy compiled output + production node_modules only
COPY --from=builder /app/dist ./dist
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Log directory (writable by mcp user)
RUN mkdir -p /app/logs && chown -R mcp:mcp /app/logs

USER mcp

EXPOSE 3890

# Health check (/health endpoint ที่สร้างไว้แล้ว)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3890/health || exit 1

CMD ["node", "dist/server.js"]
