# Backend API service. Build context: the server/ directory.
# Deploy as its own service in Dokploy, with the PostgreSQL service on the same network.
# Set the environment from server/.env.example. Never bake secrets into the image.

FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

FROM node:22-alpine AS run
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /src/dist/cli.mjs ./dist/cli.mjs
COPY migrations ./migrations
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD ["node", "dist/cli.mjs", "healthcheck"]
# Migrations are explicit: run `node dist/cli.mjs migrate up` as a one-off task before the first start of a new version.
# /readyz reports 503 while migrations are pending, so traffic is not routed to a service with an old schema.
CMD ["node", "dist/cli.mjs", "serve"]
