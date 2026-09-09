# Whitelist Cloud dashboard/server. better-sqlite3 is native, so we install the
# build toolchain (node-gyp uses a prebuilt binary when available, else compiles).
# Node 22+ is required by better-sqlite3 v13 (Node 20 segfaults on load).
FROM node:22-bookworm-slim

# Build deps for native modules (better-sqlite3) + curl for fetching Litestream.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Litestream: streams the SQLite DB to S3-compatible storage (Backblaze B2 free
# tier) for durability on hosts without a persistent disk. Optional at runtime —
# the entrypoint only uses it when B2 credentials are present.
ARG LITESTREAM_VERSION=0.3.13
RUN curl -fsSL "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-v${LITESTREAM_VERSION}-linux-amd64.tar.gz" \
      | tar -xz -C /usr/local/bin litestream \
    && litestream version

WORKDIR /app

# Install server deps first (better layer caching).
COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev

# The server reads sibling components (android/, ios/) for policy mapping.
COPY server ./server
COPY android ./android
COPY ios ./ios
COPY shared ./shared

# Android live push needs googleapis in the image (the mapping/preview works
# without it, but enterprises.policies.patch etc. require the SDK). No lockfile
# in android/, so npm install rather than ci.
RUN cd android && npm install --omit=dev --no-audit --no-fund

# Litestream config + entrypoint.
COPY server/litestream.yml /etc/litestream.yml
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent data (SQLite) lives here — mount a volume/disk at this path.
ENV DATA_DIR=/data
ENV PORT=8080
ENV HTTPS=1
VOLUME ["/data"]
EXPOSE 8080

WORKDIR /app/server
# Entrypoint restores from B2 + runs under Litestream when configured, else runs
# the server directly (ephemeral).
CMD ["/entrypoint.sh"]
