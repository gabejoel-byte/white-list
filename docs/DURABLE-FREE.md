# Durable storage for free (no card)

Render's free tier has no persistent disk, so the SQLite database would reset on
every restart. **Litestream** fixes this for free: it streams the database to
S3-compatible object storage and restores it on boot. We use **Backblaze B2**
because its free tier (10 GB) requires **no credit card**.

Nothing in the app code changes — Litestream runs alongside the server (see
`server/entrypoint.sh` and `server/litestream.yml`). If the B2 env vars are
absent, the server runs exactly as before (ephemeral).

## One-time Backblaze setup (~5 min, no card)

1. Create a free account at **https://www.backblaze.com/sign-up/cloud-storage**
   (email + password; no card).
2. **Buckets → Create a Bucket**: name it e.g. `whitelist-cloud-db`, set it
   **Private**. Note the bucket name.
3. On the bucket list, note the **Endpoint** shown, e.g.
   `s3.us-west-004.backblazeb2.com`. The region is the middle part:
   `us-west-004`.
4. **Application Keys → Add a New Application Key**: allow access to that bucket,
   read+write. Copy the **keyID** and **applicationKey** (shown once).

## The five env vars

Give me these values (or set them yourself in the Render dashboard → your
service → Environment) and I'll apply them via the API:

| Env var | Example | From |
|---|---|---|
| `B2_BUCKET` | `whitelist-cloud-db` | bucket name |
| `B2_ENDPOINT` | `s3.us-west-004.backblazeb2.com` | bucket endpoint |
| `B2_REGION` | `us-west-004` | middle of the endpoint |
| `LITESTREAM_ACCESS_KEY_ID` | `004xxxxxxxxxxxx0000000001` | application keyID |
| `LITESTREAM_SECRET_ACCESS_KEY` | `K004xxxxxxxxxxxxxxxxxxxxxxxxxxxx` | applicationKey |

Once set, the next deploy restores the DB on boot and streams every change back
to B2 (~1s sync). Your policies, enrolled devices, and enrollment keys then
**survive restarts, sleeps, and redeploys** — all on free tiers.

## Verifying it works

After the deploy, create a policy in the dashboard, then in Render **Manual
Deploy → Restart**. When it comes back, the policy is still there — that's
Litestream restoring from B2. (Without it, the policy would be gone.)
