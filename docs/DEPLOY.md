# Deploying Whitelist Cloud

The dashboard is a Docker container (`server/Dockerfile`). It needs a public
**HTTPS** URL (agents and Apple/Google devices connect to it) and a **persistent
disk** for its SQLite database.

## Option A — Render (recommended, has a free-ish tier with a disk)

1. The repo is already on GitHub. In Render: **New → Blueprint**, select this
   repo. Render reads `render.yaml`, builds `server/Dockerfile`, and deploys.
2. Set the secret env vars (marked `sync: false`) in the Render dashboard:
   - `ADMIN_PASS` — a strong password for the first `admin` login.
   - (Android, optional) `ENTERPRISE_NAME`, `GOOGLE_APPLICATION_CREDENTIALS`.
   - (iOS, optional) `MDM_SERVER_URL` = your Render URL, `MDM_TOPIC`,
     `APNS_CERT`, `APNS_KEY`.
3. Deploy. Your dashboard is at `https://whitelist-cloud-XXXX.onrender.com`.
   Every later `git push` to `main` auto-deploys.

> The `starter` plan is required for a persistent disk; the free plan has no
> disk, so the SQLite DB would reset on each deploy.

## Option B — Railway

New Project → Deploy from GitHub → this repo. Railway detects the Dockerfile.
Add a **Volume** mounted at `/data`, set the same env vars, and expose port
`8080`. Railway gives you an HTTPS URL.

## Option C — Fly.io

`fly launch` in the repo (it picks up `server/Dockerfile`), then
`fly volumes create data --size 1` and mount it at `/data` in `fly.toml`. Set
secrets with `fly secrets set ADMIN_PASS=… MDM_TOPIC=…`.

## Option D — any VPS with Docker

```bash
docker build -f server/Dockerfile -t whitelist-cloud .
docker run -d --name whitelist-cloud -p 8080:8080 \
  -v /srv/whitelist-data:/data \
  -e HTTPS=1 -e ADMIN_USER=admin -e ADMIN_PASS='StrongSecret!' \
  whitelist-cloud
```
Put it behind nginx/Caddy for TLS (Caddy gets you HTTPS in two lines).

## After it's up

1. Sign in at `/` as `admin` with your `ADMIN_PASS`.
2. **Policies** → create a policy and set an unlock key.
3. **Enrollment** → create an enrollment key.
4. Build an endpoint package pointed at your URL and install it (below).

## Shipping updates

`npm run ship` at the repo root commits everything and pushes `main`; your host
auto-deploys from the push. (Set up the host once as above.)

## Building & installing the desktop agents

**Windows** (bundles a Node runtime; nothing needed on the endpoint):
```bash
cd agent
node build.js --server https://YOUR-URL --key ENR-xxxx --zip
# -> installer/dist/WhitelistAgent.zip ; on the endpoint, as Administrator:
powershell -ExecutionPolicy Bypass -File install.ps1
```

**macOS**:
```bash
cd macos   # bundle a `node` binary beside the package, then:
sudo ./installer/install.sh --server https://YOUR-URL --key ENR-xxxx
```

## Mobile (needs the platform accounts)

- **Android**: `android/README.md` — Google Cloud project + Android Management
  API + service account + enterprise. Manage from the dashboard **Android** tab.
- **iOS**: `ios/README.md` — Apple Developer account + MDM push cert + supervised
  devices. The MDM server endpoints are built in (`/mdm/*`); set `MDM_SERVER_URL`
  + `MDM_TOPIC` (+ `APNS_CERT`/`APNS_KEY`). Manage from the **iOS** tab.

## Security checklist before real use

- Strong `ADMIN_PASS`; rotate the default immediately.
- HTTPS only (`HTTPS=1`, which is set in the Dockerfile).
- Treat enrollment keys and device tokens as secrets; revoke from the dashboard
  if leaked.
- Read `docs/SECURITY.md` for the honest threat model per platform.
