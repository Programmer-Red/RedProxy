# RedProxy server image.
#
# Build:
#   docker build -t redproxy .
# Run:
#   docker run -d --name redproxy -p 3000:3000 \
#     -e PUBLIC_BASE_URL=http://localhost:3000 \
#     -e ALLOW_INSECURE_HTTP=true \
#     -v redproxy-data:/app/data \
#     redproxy
#
# No docker-compose required.

FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NPM_CONFIG_UPDATE_NOTIFIER=false

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json tsconfig.build.json ./
COPY server ./server
COPY scripts ./scripts
COPY public ./public
COPY extension-template ./extension-template

RUN npm run build
RUN npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATA_DIR=/app/data \
    PUBLIC_BASE_URL=http://localhost:3000

WORKDIR /app

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json

RUN mkdir -p /app/data && chown -R node:node /app

USER node
EXPOSE 3000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server/src/index.js", "serve"]
