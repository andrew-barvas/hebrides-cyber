# Container build for the Azure Container Apps deploy path — see
# .github/workflows/deploy-containerapp.yml and azure/terraform/main.tf's
# azurerm_container_app resource. Not used by the default deploy.yml path
# (Azure Static Web Apps hybrid mode, where Oryx builds the app directly
# from source without this file). Keep both paths working independently;
# see CLAUDE.md's Deployment section for why SWA is still the default.

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Build-time-only public env vars — same ones deploy.yml passes to Oryx's
# build, needed here for any generateStaticParams()/build-time Supabase call.
ARG NEXT_PUBLIC_SUPABASE_URL
ARG NEXT_PUBLIC_SUPABASE_ANON_KEY
ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_SUPABASE_URL=$NEXT_PUBLIC_SUPABASE_URL
ENV NEXT_PUBLIC_SUPABASE_ANON_KEY=$NEXT_PUBLIC_SUPABASE_ANON_KEY
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL
# Switches next.config.mjs's output to 'standalone' — see that file's
# comment. Oryx's SWA build never sets this, so that path is unaffected.
ENV NEXT_OUTPUT_MODE=standalone
RUN npm run build

# Scan worker (`docker build --target scan-worker`): the queue loop
# (src/scripts/run-queued-scan-jobs.ts) plus every extended scan tool, run by
# the Azure Container Apps Job in azure/terraform/scan-workers.tf. It runs the
# TypeScript source through tsx exactly as the GitHub Actions shards do, so it
# needs the full node_modules and source, not the standalone web build. Tool
# pins live in docker/scan-tools.sh, shared with scheduled-scans.yml (the
# fallback path); SCAN_TOOLS_STRICT=1 fails the build on any missing tool.
# BuildKit only builds the stages a target needs, so building the web app
# (the default, last stage below) never builds this one.
FROM node:22-slim AS scan-worker
WORKDIR /app
ENV SCAN_TOOLS_STRICT=1
# Shared location so the non-root user can launch the browser installed as root.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
COPY docker/scan-tools.sh /usr/local/bin/scan-tools.sh
COPY src/worker/tools/wordlists ./src/worker/tools/wordlists
RUN bash /usr/local/bin/scan-tools.sh system /app && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1001 scanner
COPY --from=deps --chown=scanner /app/node_modules ./node_modules
# The base suite's playwright.ts launches Chromium; npm ci doesn't download it.
RUN npx playwright install --with-deps chromium && rm -rf /var/lib/apt/lists/*
COPY --chown=scanner . .
USER scanner
ENV PATH=/home/scanner/.local/bin:$PATH
RUN bash /usr/local/bin/scan-tools.sh user /app && bash /usr/local/bin/scan-tools.sh verify /app
# Paths the tool wrappers read; the workflow sets the same ones in its env.
ENV TESTSSL_PATH=/opt/testssl.sh/testssl.sh \
  KITERUNNER_WORDLIST=/opt/kiterunner/api-routes.kite \
  CONTENT_DISCOVERY_WORDLIST=/app/src/worker/tools/wordlists/content-dirs.txt \
  ZAP_API_URL=http://127.0.0.1:8090
CMD ["bash", "docker/scan-worker-entrypoint.sh"]

# The web app. Keep this the LAST stage: deploy-containerapp.yml builds the
# default target.
FROM node:22-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
# Standalone output doesn't include static assets — copy them explicitly.
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
CMD ["node", "server.js"]
