# syntax=docker/dockerfile:1.7
# Keep the Docker base on Node 22 because the official Node 24/25 slim images
# no longer publish linux/arm/v7 manifests, which breaks our armv7 Docker jobs.
FROM node:22-bookworm-slim AS builder

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

ENV PYTHON=/usr/bin/python3

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
RUN npm rebuild esbuild sharp better-sqlite3 --no-audit --no-fund

COPY . .
RUN npm run build:web && npm run build:server
RUN --mount=type=cache,target=/root/.npm npm prune --omit=dev --no-audit --no-fund

FROM node:22-bookworm-slim

WORKDIR /app

ARG TARGETARCH
ARG TARGETVARIANT
ARG KUBECTL_VERSION=v1.31.8
ARG HELM_VERSION=v3.18.6

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tar gzip \
  && case "$TARGETARCH" in \
    amd64|arm64) export ARCH="$TARGETARCH" ;; \
    arm) \
      if [ "${TARGETVARIANT:-}" = "v7" ]; then \
        export ARCH="arm"; \
      else \
        echo "Unsupported TARGETARCH/TARGETVARIANT: $TARGETARCH/${TARGETVARIANT:-}" >&2; exit 1; \
      fi ;; \
    *) echo "Unsupported TARGETARCH/TARGETVARIANT: $TARGETARCH/${TARGETVARIANT:-}" >&2; exit 1 ;; \
  esac \
  && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
  && chmod +x /usr/local/bin/kubectl \
  && curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH}.tar.gz" -o /tmp/helm.tgz \
  && tar -xzf /tmp/helm.tgz -C /tmp \
  && mv "/tmp/linux-${ARCH}/helm" /usr/local/bin/helm \
  && chmod +x /usr/local/bin/helm \
  && rm -rf /tmp/helm.tgz "/tmp/linux-${ARCH}" /var/lib/apt/lists/*

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/drizzle ./drizzle

RUN mkdir -p /app/data

EXPOSE 4000

ENV NODE_ENV=production
ENV DATA_DIR=/app/data

CMD ["sh", "-c", "node dist/server/db/migrate.js && node dist/server/index.js"]
