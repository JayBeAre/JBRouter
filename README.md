# JBRouter

A modular Cloudflare Worker that exposes an **Anthropic-compatible `/v1/messages` endpoint**, backed by your configured AI providers (Gemini, OpenCode Zen, etc.). Point Claude Code (or any Anthropic API client) at it, and it silently routes requests to your chosen backends.

## Features

- **Modular Architecture**: Cleanly separated backend (`src/`) and frontend (`public/`).
- **Role-based routing** — requests naming `opus`, `sonnet`, `haiku` (or custom keywords) get routed to a **pool** of your choosing.
- **Pools are ordered fallback lists** — each pool tries its provider+model entries in order until one succeeds.
- **Cross-pool fallback** — if every entry in a pool fails, it can fall through to another pool.
- **Everything is editable live** at `/admin` — providers, pools, role mapping, and API keys.
- **No Worker Secrets required** — all configuration lives in a Cloudflare KV namespace.

## Requirements

- A Cloudflare account with Workers + KV enabled.
- [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed.

## Install and Deploy

**1. Create a KV namespace**

```bash
npx wrangler kv:namespace create CONFIG_KV
```

Copy the `id` it prints out.

**2. Configure `wrangler.toml`**

Ensure `wrangler.toml` exists in the root with the following:

```toml
name = "jbrouter"
main = "src/index.ts"
compatibility_date = "2026-09-06"

[assets]
directory = "public"

[[kv_namespaces]]
binding = "CONFIG_KV"
id = "<PASTE_YOUR_NAMESPACE_ID_HERE>"
```

**3. Deploy**

```bash
npx wrangler deploy
```

**4. Log in and set your password**

Visit `https://<your-worker>.workers.dev/admin`, log in with the default password (`changeme123`), and you will be forced to pick a new password.

**5. Configure**

Use the Admin panel at `/admin` to:
- **Providers**: Add API keys and Base URLs.
- **Pools**: Define fallback logic.
- **Role Mapping**: Route model names to pools.
- **Security**: Manage admin password and API authentication.

**6. Point your client at it**

```bash
export ANTHROPIC_BASE_URL="https://<your-worker>.workers.dev"
export ANTHROPIC_AUTH_TOKEN="your-token" # only if enabled in Security tab
```

## Notes

- Provider API keys are stored in KV.
- Check `/health` for a quick liveness check.
