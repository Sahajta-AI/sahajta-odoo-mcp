# Odoo setup

## 1. Check that your plan allows API access

Odoo allows its external API (which every integration, including this one, uses) only on the **Custom**
pricing plan. On *One App Free* or *Standard* the connection is refused. Check your subscription in Odoo or
ask your Odoo account manager before deploying.

## 2. Decide who gets access, and with what rights

The connector acts **as the person who signs in**, with exactly their Odoo permissions. So:

* Let people connect with their **normal employee account**: they'll see in Claude what they see in Odoo.
* Avoid connecting with **administrator** accounts. Admins can read everything (all salaries, all invoices),
  and that data then flows into Claude conversations.
* Only internal users can connect; portal/customer accounts are refused automatically.
* Restrict sign-ins to company e-mails with `MCP_ALLOWED_LOGIN_DOMAINS=sahajta.ai`.
* For extra caution, block sensitive apps for everyone with `MCP_BLOCKED_MODELS` (e.g. `hr.payslip*,hr.contract*`).

## 3. Review Odoo automations before enabling changes

In `read_write` mode, pressing a button or saving a record through Claude triggers the same automations as in
the Odoo UI (automation rules, confirmation e-mails, stock moves, …). Glance at
*Settings → Technical → Automation Rules* (developer mode) and the e-mail options in Sales/Inventory
settings so there are no surprises.

## Create an API key

Each person does this once:

1. In Odoo, click your profile picture (top right) → **My Preferences**.
2. Open the **Security** tab (called *Account Security* in older versions) → **Create API Key** (*Add API Key* /
   *New API Key* in older versions), and confirm your password.
3. Name it `Claude`. If Odoo asks for a **scope** (Odoo 19.4 / 20 and later), choose **RPC**. The *MCP* scope is
   for Odoo's own built-in MCP server and will **not** work here.
4. Duration: regular employees can choose up to 3 months; only administrators can create keys that never expire.
   When a key expires, the person reconnects the connector in Claude with a new key.
5. Copy the key immediately. Odoo shows it only once. Paste it into the Claude sign-in page.

> **Upgrading to Odoo 20?** Keys created on Odoo 19 or earlier stop working on Odoo 20 (it requires the RPC
> scope). After the upgrade, everyone creates a new key and reconnects the connector.

To revoke Claude's access at any time, delete that key on the same tab. It stops working immediately.
Administrators can see and delete everyone's keys under *Settings → Users & Companies → API Keys* ("Manage API
Keys"). Archiving an Odoo user also disables their keys.

> Two-factor authentication doesn't interfere: API keys are made to work alongside 2FA.

## Odoo versions

Odoo Online databases currently run 18.0, 19.0, 19.3, 19.4 or 20.0. The server detects the version on its own:
it uses Odoo's JSON-2 API on 19.0+ and falls back to the older JSON-RPC API on 18.0. Odoo removes JSON-RPC from
Odoo Online in 21.1 (winter 2027), so upgrading to 19+ before then keeps everything working.

## API usage limits

Odoo Online's acceptable-use policy asks integrations to throttle calls (roughly one call per second, no
parallel calls, for short bursts). The server therefore sends Odoo **one request at a time** across all users
(`ODOO_MAX_PARALLEL_REQUESTS=1`), caches field definitions, retries a read once if Odoo is busy, and never
retries a change automatically. If you run Odoo.sh or your own Odoo server you may raise the limit.

## About Odoo's own MCP server

Recent Odoo Enterprise versions (saas-19.4 / 20) include a built-in MCP server in the AI app. It is read-only by
default and admin-curated, but it is closed source, has no OAuth sign-in for Claude's connector directory,
and doesn't offer this server's preview/approval flow for changes. You can use both side by side.
