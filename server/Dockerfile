# Whitelist Cloud dashboard/server. better-sqlite3 is native, so we install the
# build toolchain (node-gyp uses a prebuilt binary when available, else compiles).
FROM node:20-bookworm-slim

# Build deps for native modules (better-sqlite3). Kept minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install server deps first (better layer caching).
COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev

# The server reads sibling components (android/, ios/) for policy mapping.
COPY server ./server
COPY android ./android
COPY ios ./ios
COPY shared ./shared

# Persistent data (SQLite) lives here — mount a volume/disk at this path.
ENV DATA_DIR=/data
ENV PORT=8080
ENV HTTPS=1
VOLUME ["/data"]
EXPOSE 8080

WORKDIR /app/server
CMD ["node", "src/index.js"]
