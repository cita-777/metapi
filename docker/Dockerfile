FROM node:25-bookworm-slim AS builder

WORKDIR /app

ARG TARGETARCH

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ENV PYTHON=/usr/bin/python3

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
RUN npm rebuild esbuild sharp better-sqlite3 --no-audit --no-fund

COPY . .
RUN npm run build:web && npm run build:server

# Bundle the server entrypoints while keeping runtime packages (including
# better-sqlite3) external so their native ABI remains target-specific.
RUN node_modules/.bin/esbuild dist/server/index.js \
  --bundle --platform=node --format=esm --target=node25 --packages=external \
  --outfile=dist/server/index.js.tmp \
  && mv dist/server/index.js.tmp dist/server/index.js \
  && node_modules/.bin/esbuild dist/server/db/migrate.js \
  --bundle --platform=node --format=esm --target=node25 --packages=external \
  --outfile=dist/server/db/migrate.js.tmp \
  && mv dist/server/db/migrate.js.tmp dist/server/db/migrate.js

# Keep an immutable bootstrap bundle in the image.  All user-triggered
# versions are written to the persistent runtime volume instead.
RUN mkdir -p /tmp/metapi-bootstrap \
  && cp -a dist drizzle package.json /tmp/metapi-bootstrap/ \
  && npm prune --omit=dev --no-audit --no-fund \
  && npm rebuild better-sqlite3 --no-audit --no-fund \
  && find node_modules -type f -name 'test_extension.node' -delete \
  && cp -a node_modules /tmp/metapi-bootstrap/node_modules \
  && find /tmp/metapi-bootstrap -type l -delete \
  && case "$TARGETARCH" in amd64|arm64) ;; *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; esac \
  && TARGETARCH="${TARGETARCH}" node -e "const fs=require('node:fs'); const p=require('./package.json'); const arch=process.env.TARGETARCH; fs.writeFileSync('/tmp/metapi-bootstrap/release.json', JSON.stringify({schemaVersion:1,version:p.version,channel:'stable',platform:'linux',arch,nodeMajor:25,entrypoint:'dist/server/index.js',migrationEntrypoint:'dist/server/db/migrate.js',artifactName:null,artifactSha256:null,gitSha:process.env.GITHUB_SHA||null},null,2)+'\\n')"

FROM node:25-bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ENV NODE_ENV=production
ENV DATA_DIR=/app/data
ENV UPDATE_CENTER_RUNTIME_DIR=/app/runtime
ENV UPDATE_CENTER_RUNTIME_PERSISTENT=true
ENV METAPI_BOOTSTRAP_DIR=/app/bootstrap

COPY --from=builder /tmp/metapi-bootstrap ./bootstrap
COPY scripts/runtime/docker-runner.mjs ./docker-runner.mjs

RUN mkdir -p /app/data /app/runtime \
  && printf 'true\n' > /app/runtime/.persistent

VOLUME ["/app/data", "/app/runtime"]

EXPOSE 4000

CMD ["node", "/app/docker-runner.mjs"]
