# Deploying on Vercel

The connector runs as a Python function (`app.py`) with Upstash Redis for shared state (sign-ins,
one-time approvals, rate limits). Vercel functions keep no files and can run as several copies at once,
so Redis is required; the app refuses to start without it.

## Project settings

| Setting | Value |
|---|---|
| Project | `sahajta-odoo-mcp` (framework preset: Python) |
| Region | `bom1` (Mumbai), close to the Odoo database |
| Deployment protection | Standard: previews are private, the production domain is public (Claude must reach it) |
| Plan | Vercel's terms require **Pro** for commercial use |

## Environment variables

| Variable | Value |
|---|---|
| `ODOO_URL` | `https://sahajta.odoo.com` |
| `ODOO_PROTOCOL` | `json2` (Odoo 19+). Do not use `auto` here: each new function instance would test the connection again. `ODOO_DB` is not needed |
| `MCP_PUBLIC_URL` | the production URL, e.g. `https://sahajta-odoo-mcp.vercel.app` (no trailing slash) |
| `MCP_SECRET` | random 48+ characters (sensitive). Changing it signs everyone out |
| `MCP_ALLOWED_LOGINS` | `person@example.com`: the only Odoo login that may connect |
| `MCP_ACCESS_MODE` | `read_only` to start; `read_write` to allow changes (with preview + approval) |
| `MCP_ALLOW_OUTBOUND_MESSAGES` | `true` lets Claude send e-mails and press "Send" buttons (with preview + approval). Default `false` |
| `MCP_ALLOW_ARCHIVE` | `true` lets Claude archive and unarchive records (with preview + approval). Default `false` |
| `MCP_ALLOW_CANCEL_ACTIONS` | `true` lets Claude press cancel / reset to draft / mark lost buttons (with approval). Default `false` |
| `MCP_TRUST_PROXY_HEADERS` | `true` |
| `MCP_ADMIN_TOKEN` | random 40+ characters (sensitive): unlocks the usage report |
| `REDIS_URL` / `KV_URL` | set automatically when Upstash Redis is connected to the project |

No Odoo API key is stored in Vercel. The person connecting types their login and key on the sign-in page;
the key is stored encrypted (with `MCP_SECRET`) in Redis.

After changing a variable, redeploy for it to take effect.

## Connecting Claude

1. In Claude: *Settings → Connectors → Add custom connector*.
2. Name `Sahajta Odoo`, URL `https://sahajta-odoo-mcp.vercel.app/mcp`. Leave the OAuth fields empty.
3. Click **Connect**. A sign-in page opens: enter the Odoo login and the Odoo API key.
4. In the connector's tool permissions, keep every change tool on **Needs approval**.

## Operations

* **Cut off access instantly:** delete the API key in Odoo (*My Preferences → Account Security*).
* **Usage report (last 1–30 days):** run `sahajta-odoo-mcp usage --days 7` from the project folder. It needs
  `MCP_PUBLIC_URL` and `MCP_ADMIN_TOKEN` in your local `.env` (the same token as the Vercel variable). It shows
  calls per day and per tool, who used it, changes made, and recent problems (errors and blocked actions).
  Add `--json` for raw data. The history lives in Upstash Redis for 30 days and holds only metadata: tool,
  model, field names, record counts and outcome, never any values. Without `MCP_ADMIN_TOKEN` the report is off.
* **See live logs:** Vercel → project → Logs (the free plan keeps about one hour). Every tool call is a JSON line
  with `"event": "odoo_mcp_call"`.
* **Revoke the sign-in from your laptop:** with `REDIS_URL` set to the Upstash URL in your shell, run
  `python -m sahajta_odoo_mcp.oauth.admin list` / `revoke --login person@example.com`.
* **Switch to read-write:** set `MCP_ACCESS_MODE=read_write`, redeploy, then reconnect in Claude so it sees the
  new tools. Do the same after you change `MCP_ALLOW_OUTBOUND_MESSAGES` (it adds or removes the e-mail tools).
* **Delete:** no setting allows it. Use archive instead: archived records can be restored.
