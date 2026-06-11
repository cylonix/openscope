# Next.js standalone build for the dashboards.
# Requires output: 'standalone' in next.config.ts (set at production deploy
# time via NEXT_PUBLIC_OUTPUT_STANDALONE=true env, or update the config).

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS run
WORKDIR /app
RUN addgroup -S openscope && adduser -S openscope -G openscope
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Standalone server keeps only the minimal node_modules it needs.
COPY --from=build --chown=openscope:openscope /app/.next/standalone ./
COPY --from=build --chown=openscope:openscope /app/.next/static ./.next/static
COPY --from=build --chown=openscope:openscope /app/public ./public
USER openscope
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
CMD ["node", "server.js"]
