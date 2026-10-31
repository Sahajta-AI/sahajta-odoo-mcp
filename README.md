# Sahajta Odoo MCP

Connects Claude (web, desktop, mobile, Claude Code) to Sahajta AI's Odoo, so anyone on the team can ask
things like *"show me open opportunities over ₹5L by stage"*, *"create a quotation for Acme with 3 licences"* or
*"log a note on this lead"*, and Claude works on the real Odoo data.

It is built safety-first, because all company data lives in Odoo:

| Guarantee | How |
|---|---|
| **Almost nothing can be deleted** | One delete tool, for three kinds of records only: draft invoices/bills that never had a number, cancelled quotations, archived leads (checked with Odoo before the approval and again right before deleting). `unlink` is refused on every other path; lines can be removed only from quotations, RFQs and draft invoices. |
| **Claude acts as the person, never as admin** | Each employee signs in with their *own* Odoo API key. Odoo's normal permissions and record rules apply to everything. |
| **Read-only unless you switch it on** | Default mode exposes search/read/report tools only. Change tools don't even appear until `MCP_ACCESS_MODE=read_write`. |
| **No hallucinated changes** | Every field name, choice value and record id is checked against the live Odoo before anything is sent; unknown ones are rejected with a "did you mean…?" hint. |
| **Human approves every change** | Each change is previewed first (current → new values, with names behind ids). Applying it needs a signed token from that exact preview, and the token dies if anything changed meanwhile. Change tools are marked *destructive*, so Claude always asks before running them. |
| **Workflows stay intact** | Status fields (`state`) can't be written directly; only real Odoo buttons (Confirm, Validate, …) can be pressed, and cancel/reset/archive/e-mail buttons are off by default. |
| **Secrets stay secret** | Passwords, API keys, tokens and system configuration models are never readable; Odoo keys are encrypted at rest. |
| **Audit trail** | Odoo records every change under the person's own name; this server also logs every call (ids and field names, never values). |

See [docs/SECURITY.md](docs/SECURITY.md) for the full list of protections and the threat model.

## Before you start: one Odoo requirement

Odoo only allows its external API on the **Custom** pricing plan (not on One App Free or Standard).
Check *Odoo → Settings → your subscription*, or ask your Odoo account manager. Without it, no Odoo
integration (this one, Odoo's own MCP, or any community server) can connect.

## What Claude can do

| Tool | What it does | Mode |
|---|---|---|
| `odoo_whoami` | Who am I, which company, what is allowed, the bill inbox address | always |
| `odoo_help` | Per area: what Claude can and cannot do, and the person's own steps in Odoo (every refusal points here) | always |
| `odoo_list_models` | Find the model for a concept ("invoice" → `account.move`) | always |
| `odoo_describe_model` | Fields, labels, choices, what may be written | always |
| `odoo_search` / `odoo_read` / `odoo_count` | Find and read records | always |
| `odoo_aggregate` | Totals and breakdowns computed by Odoo (revenue by month, pipeline by stage) | always |
| `odoo_find` | Turn a name the person mentions into the right record | always |
| `odoo_list_actions` | The buttons on a model's screens and whether the AI may press them | always |
| `odoo_preview_create` → `odoo_create` | Create records (with order lines etc.) | read_write |
| `odoo_preview_update` → `odoo_update` | Change field values | read_write |
| `odoo_preview_action` → `odoo_run_action` | Press a workflow button (confirm order, validate…) | read_write |
| `odoo_preview_delete` → `odoo_delete` | Delete a never-numbered draft invoice/bill, a cancelled quotation or an archived lead | read_write |
| `odoo_add_note` | Log an internal note in the chatter (nobody is e-mailed) | read_write |
| `odoo_preview_message` → `odoo_send_message` | Message a record's followers (e-mails customers) | read_write + outbound |

Because it works on Odoo's generic model API, it covers **every installed app**: CRM, Sales, Invoicing,
Inventory, Purchase, Project, HR, Helpdesk, Studio models, and so on, always within the person's permissions.

## Setup

1. **Odoo side** – [docs/ODOO_SETUP.md](docs/ODOO_SETUP.md): check the plan, decide who gets access, and how each
   person creates an API key.
2. **Deploy**: on Vercel + Upstash Redis ([docs/DEPLOY_VERCEL.md](docs/DEPLOY_VERCEL.md), how Sahajta runs it), or
   with the Docker image on any small server with HTTPS ([docs/DEPLOY.md](docs/DEPLOY.md)). Then add it to Claude
   as a connector.
3. **Each employee** – in Claude: *Settings → Connectors → Sahajta Odoo → Connect*, then enter their Odoo login
   and API key on the sign-in page.

### Just for yourself, on your laptop (Claude Desktop / Claude Code)

```bash
pip install .
```

Then add to Claude Desktop's config (*Settings → Developer → Edit Config*) or `claude mcp add`:

```json
{
  "mcpServers": {
    "sahajta-odoo": {
      "command": "sahajta-odoo-mcp",
      "args": ["stdio"],
      "env": {
        "ODOO_URL": "https://sahajta.odoo.com",
        "ODOO_DB": "sahajta",
        "ODOO_LOGIN": "you@sahajta.ai",
        "ODOO_API_KEY": "<your Odoo API key>",
        "MCP_ACCESS_MODE": "read_only"
      }
    }
  }
}
```

Check the connection any time with `sahajta-odoo-mcp check` (reads the same environment variables).

## Configuration

All settings are environment variables; [.env.example](.env.example) documents each one. The important ones:

| Variable | Default | Meaning |
|---|---|---|
| `MCP_ACCESS_MODE` | `read_only` | `read_write` enables the change tools |
| `MCP_REQUIRE_PREVIEW` | `true` | changes need a confirmed preview |
| `MCP_ALLOW_ARCHIVE` | `false` | allow archiving/unarchiving |
| `MCP_ALLOW_CANCEL_ACTIONS` | `false` | allow cancel / reset to draft / mark lost buttons |
| `MCP_ALLOW_OUTBOUND_MESSAGES` | `false` | allow anything that e-mails/messages people |
| `MCP_WRITABLE_MODELS` | *(all business models)* | restrict changes to a list, e.g. `crm.lead,res.partner,project.task` |
| `MCP_BLOCKED_MODELS` / `MCP_READONLY_MODELS` | *(none)* | extra restrictions, globs allowed (`hr.*`) |
| `MCP_MAX_WRITE_RECORDS` | `100` | max records one create or edit may touch (hard cap 100) |
| `MCP_MAX_ACTION_RECORDS` | `20` | max records one button, dialog, message or delete may touch (hard cap 100) |
| `MCP_CONFIRM_TTL_SECONDS` | `3600` | how long an approved preview stays usable (hard cap 24 hours) |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                      # offline unit tests
.venv/bin/pytest -m integration       # against a disposable Odoo, see tests/test_live_odoo.py
```

Tested end to end against Odoo **18.0, 19.0 and 20.0** (Community, with demo data), over both of Odoo's APIs:
JSON-2 on 19+ and legacy JSON-RPC (Odoo removes it from Odoo Online in 21.1 and from Odoo 22). The protocol is
detected automatically. Built on the official MCP Python SDK v2.

Test suites: `pytest` runs ~950 offline tests (policy, validation, tokens, formatting, client, OAuth); with a
disposable Odoo, `pytest -m integration` runs the live tests and `tests/e2e_http_connector.py` drives the
complete connector sign-in flow over HTTP.
