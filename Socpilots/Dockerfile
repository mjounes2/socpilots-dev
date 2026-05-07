# ── Build stage: install dependencies ──
FROM node:20-alpine AS deps
WORKDIR /app
COPY backend/package.json ./
RUN npm install --production --no-audit --silent

# ── Runtime stage ──
FROM node:20-alpine
WORKDIR /app

# Copy node_modules from build stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application files only (NO .env baked in)
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Security: non-root user
RUN addgroup -g 1001 -S soc && \
    adduser  -u 1001 -S soc -G soc && \
    mkdir -p /app/evidence && \
    chown -R soc:soc /app

USER soc
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=15s --start-period=30s --retries=5 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "backend/src/server.js"]
