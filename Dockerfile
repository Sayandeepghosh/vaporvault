# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# VaporVault production image
#
# Multi-stage so the runtime image carries no toolchain, no dev dependencies and
# no source. Runs as an unprivileged user on Next.js' standalone output.
# ---------------------------------------------------------------------------

FROM node:22.23.2-alpine AS base
# Next.js' SWC binaries expect glibc-compatible symbols on Alpine.
RUN apk add --no-cache libc6-compat
ENV NEXT_TELEMETRY_DISABLED=1

# --- dependencies ----------------------------------------------------------
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# `npm ci` installs devDependencies too: the build needs TypeScript and Tailwind.
RUN npm ci

# --- build -----------------------------------------------------------------
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# No secrets are needed at build time: configuration is validated on first request,
# never at module load, so nothing sensitive can be baked into an image layer.
RUN npm run build

# --- runtime ---------------------------------------------------------------
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 --ingroup nodejs vaporvault

# `standalone` bundles only the server code and the modules it actually imports.
COPY --from=builder --chown=root:root /app/.next/standalone ./
COPY --from=builder --chown=root:root /app/.next/static ./.next/static

# Application files stay read-only to the process that serves them.
USER vaporvault

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
