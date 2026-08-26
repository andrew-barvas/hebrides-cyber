# Container build for the Azure Container Apps deploy path — see
# .github/workflows/deploy-containerapp.yml and azure/terraform/main.tf's
# azurerm_container_app resource. Not used by the default deploy.yml path
# (Azure Static Web Apps hybrid mode, where Oryx builds the app directly
# from source without this file). Keep both paths working independently;
# see CLAUDE.md's Deployment section for why SWA is still the default.

FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-slim AS builder
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

FROM node:20-slim AS runner
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
