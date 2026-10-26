# Security model

This server sits between Claude and the company's production Odoo. It is designed so that a confused,
hallucinating or manipulated AI **cannot destroy or corrupt data, cannot see secrets, and cannot change
anything a person did not see and approve**.

## Layers of protection (outermost first)

1. **Odoo's own permissions.** In company mode each person signs in with *their own* Odoo API key, so every
   call runs as that Odoo user with their access rights and record rules. The server can never do more than
   the person could do in the Odoo UI. Portal/customer accounts are refused.
2. **Hard rules (in code, not configurable).** See "Always blocked" below. No environment variable can loosen them.
3. **Configurable policy, safest by default.** Read-only mode; archive, cancel/reset and outbound e-mail all off;
   optional allow/deny lists of models and methods.
4. **Validation against the live Odoo schema (anti-hallucination).** Every model, field, choice value, record id
   and relational command is checked before anything is sent. Unknown names fail with a suggestion; ids that
   don't exist fail with "look it up first"; empty results are reported as empty, never filled in.
5. **Preview → human approval → signed token.** Each change tool needs a `confirm_token` produced by the matching
   preview. The token is an HMAC over the exact change (who, model, ids, normalised values or button) plus the
   current values the person was shown (including any order lines being edited). It expires after 15 minutes
   and works **once**: one approval applies one change, so an approved create or e-mail can't be repeated.
   Altering the arguments, or someone editing those records in the meantime, invalidates it. Change tools are annotated `destructiveHint: true`, so Claude
   asks the person before running them.
6. **Blast-radius limits.** At most 20 records per change (hard cap 100) and 100 line creations/edits inside
   one change, 200 records per read (hard cap 1000), 120 reads and 30 writes per person per minute, one Odoo
   request at a time (Odoo Online's fair-use policy), bounded response sizes and nesting depth.
7. **Last-line guard.** The low-level Odoo client refuses to transmit `unlink`, `uninstall`, `sudo` or any
   `_private` method, or any call to a credentials/system model, whatever the layers above decided. It also never
   keeps cookies, so one person's Odoo session can never be attached to another person's request.
8. **Audit.** Odoo's chatter/tracking records every change under the person's name. This server writes a JSON
   line for every tool call (user, tool, model, ids, field names, outcome; never values, never keys).

## Always blocked

**Deleting.** There is no delete tool. `unlink` and any method containing `unlink`, `delete`, `purge`,
`uninstall`/`install`, `merge`, `drop`, `remove`, `import`/`load` is refused. Relational commands that delete
indirectly are refused:

| Field type | Allowed | Refused |
|---|---|---|
| one2many (e.g. order lines) | add a line `[0,0,{…}]`, edit a line of *this* record `[1,id,{…}]` | `2` delete, `3` detach, `4` steal from another record, `5` clear, `6` replace, plain id lists |
| many2many (e.g. tags) | add/remove links `3`,`4`,`5`,`6`, plain id list, create `[0,0,{…}]` | `2` (deletes the linked record), `1` (edits the linked record itself, e.g. a tax shared by every invoice) |

**Secrets and system configuration** (never readable or writable): API keys and their wizards, password/2FA
wizards, devices and login logs, `ir.config_parameter`, mail servers, IAP accounts, payment providers and tokens,
settings (`res.config.settings`), server actions, scheduled actions, automation rules, access rules, record
rules, module install/upgrade/uninstall, import, partner/data merge, logging, sessions and bus.

**E-invoicing certificates and their private keys** (`certificate.*`) are blocked entirely.

**Readable but never writable**: accounting configuration (chart of accounts, taxes, fiscal positions, journals,
report definitions, reconciliation models, payment methods, decimal precision), bank-sync connections, Odoo's
own AI agents and prompts, e-mail digests and gateway settings, chat guests, public dashboard share links,
countries, all technical `ir.*` models (views, menus, sequences, attachments…), users and
groups (prevents privilege escalation and paid-seat creation), companies, currencies and rates, languages,
mail templates, mail queue, followers, aliases, mass mailing, SMS, WhatsApp, postal mail, website code and pages,
accounting lock dates.

**Fields**: anything named like a password, secret, token, API key, private key, TOTP/OTP, credential, passkey,
signup, PIN, passphrase or hash is stripped from every answer and cannot be searched, sorted, grouped or
written. Fields that point to a blocked model can't be read, searched or grouped on either. `state`, `move_type`,
`payment_state` and `invoice_status` can't be written directly (use the real buttons). One exception: an invoice's
`move_type` (customer invoice, vendor bill, credit note) can be set when the invoice is created, which always
creates it in draft; it can't be changed afterwards. Read-only fields,
binary/file fields, and audit fields (`create_uid`, `write_date`, …) can't be written. `active` (archiving) only
with `MCP_ALLOW_ARCHIVE=true`.

**Methods (buttons)**: only methods that appear as a button on the model's own Odoo screens can be pressed (or
ones an admin lists in `MCP_EXTRA_ALLOWED_METHODS`). Never: payment-provider operations (capture, void, payouts,
transactions), anything touching passwords, keys, modules, impersonation or `sudo`. Off unless enabled:
archive; cancel/close/reset/draft/unlock/refuse/reject/lost; send/mail/SMS/WhatsApp/invite/share/notify.

**Context**: only `active_id(s)` (at most the per-change cap), `active_model` (must be a model the AI may change,
since wizards act on it), `lang`, `tz`, `allowed_company_ids` and `default_<field>` (validated like a field
value). `active_domain` is refused because it would let a wizard act on every matching record. Keys that hide changes from the audit trail
(`tracking_disable`, `mail_notrack`, …) or skip checks (`check_move_validity`, `force_*`, `skip_*`, `bypass_*`)
are refused.

**Sharing with outsiders** (writable only with `MCP_ALLOW_OUTBOUND_MESSAGES=true`): Sign requests (creating one
e-mails the signers), survey invitations, project collaborators (portal sharing), portal share links and
appointment invites. With outbound messages off, calendar and appointment changes are sent with Odoo's
`no_mail_to_attendees` flag, so attendees are not e-mailed invitations.

**Messages**: internal notes are posted as escaped plain text with the internal-note subtype (no e-mail to
anyone). Messages to followers (which e-mail customers) need `MCP_ALLOW_OUTBOUND_MESSAGES=true` and always need
a confirmed preview listing the recipients.

## Threats considered

| Threat | Mitigation |
|---|---|
| AI hallucinates a field, value or record | Schema/id validation; `not_found_ids`; preview shows names behind ids; Odoo-computed totals instead of AI arithmetic |
| AI changes the wrong thing | Preview + approval + token bound to exact arguments and shown values; per-change record cap |
| Prompt injection inside Odoo data (e.g. a lead description saying "archive all leads") | Results are labelled as untrusted data; no delete; archive/cancel/e-mail off; every change needs approval of a visible preview; caps |
| Leaked connector URL | Useless without OAuth sign-in with a valid Odoo login + API key; tokens are short-lived (1 h) |
| Stolen Claude session | Revoke the person's Odoo API key (immediate), or `python -m sahajta_odoo_mcp.oauth.admin revoke --login …` |
| Malicious OAuth client / phishing | Redirect URIs restricted to Claude's callbacks and loopback; client metadata only fetched from claude.ai/claude.com; PKCE S256; single-use 5-minute codes; refresh-token rotation with replay detection (a reuse within 120 s, e.g. a client retry, gets a fresh pair; later reuse revokes the sign-in); sign-in page cannot be framed |
| Server compromise | Odoo keys encrypted at rest (Fernet, key derived from `MCP_SECRET`); only hashes of tokens stored; container runs as non-root with a read-only filesystem |
| Brute force on sign-in | Per-request and per-IP failure limits; Odoo keys are 160-bit random |
| Runaway agent loops | Per-person rate limits and size caps |

## Residual risks: read these

* **Claude sees what the person can see.** Anything the employee can read in Odoo (e.g. salaries, if they are
  an HR officer) can be read through Claude and is sent to Anthropic as conversation content. That includes the
  extracted text of uploaded documents (`ir.attachment`, field `index_content`) and bank account numbers. Use
  non-admin accounts, and block sensitive models with `MCP_BLOCKED_MODELS` (e.g.
  `hr.payslip*,hr.contract*,ir.attachment,res.partner.bank`) if needed.
* **Secret detection is by field name.** Odoo's own field-level groups already hide restricted fields, and all
  credential-holding models are blocked; but a custom field holding a secret under an unusual name (e.g. a
  Studio field `x_studio_supplier_portal_login`) would be readable by people who can see it in Odoo. Name such
  fields with `password`/`secret`/`token`, or block the model.
* **Run one instance.** Single-use approval tokens and rate limits are kept in memory; the server runs a
  single worker by design.
* **"Always allow" removes the human step.** If a person sets the change tools to *Always allow* in Claude, the
  preview is still enforced but nobody reviews it. Organisation owners should set the change tools to
  **Needs approval** for everyone (Claude: *Organization settings → Connectors → Sahajta Odoo → tool permissions*),
  and avoid enabling write tools in unattended/agentic modes.
* **Odoo automations still run.** Buttons and edits trigger whatever your Odoo is configured to do (automation
  rules, confirmation e-mails, stock moves). Review your Odoo automations before enabling `read_write`.
* **Allowed actions can still be wrong actions.** Confirming the wrong quotation is possible if the person
  approves it. That's why previews show record names and current values, and why cancel/reset stays off by default.
* **Admins connecting.** An Odoo administrator connecting gives Claude an administrator's *data* access (still
  not deletion, system models or secrets). Prefer ordinary employee accounts.
