---
name: alert-rules
description: Create, update, list and delete three.ws pump.fun alert rules and read fired-alert history through the alerts-mcp tools. Use when asked to watch a coin or agent and be notified in-app, by webhook or on Telegram.
---

# three.ws alert rules

The plugin starts `@three-ws/alerts-mcp` over stdio (`npx -y @three-ws/alerts-mcp`). Every tool is scoped to the signed-in three.ws account, so it needs a session.

## Environment

- `THREE_WS_SESSION` (required): the value of the `__Host-sid` cookie from a signed-in three.ws browser session. The server sends it as that cookie, and fetches a one-time CSRF token from `/api/csrf-token` before each write. Treat it like a password. Never print it or write it into a file.
- `THREE_WS_BASE`: API origin, default `https://three.ws`.
- `THREE_WS_TIMEOUT_MS`: per-request timeout in milliseconds.

Without `THREE_WS_SESSION`, tools fail with code `no_session`. Tell the user how to set it.

## Tools

| Tool | Arguments | Endpoint |
| --- | --- | --- |
| `list_alert_rules` | none | `GET /api/alerts/rules` |
| `create_alert_rule` | `kind`, `target_mint`, `target_agent`, `threshold`, `deliver_in_app`, `webhook_url`, `telegram_chat`, `cooldown_seconds`, `enabled`, `label` | `POST /api/alerts/rules` |
| `update_alert_rule` | `rule_id` plus any create field (partial; `null` clears a nullable field) | `PATCH /api/alerts/rules/{rule_id}` |
| `delete_alert_rule` | `rule_id` (UUID) | `DELETE /api/alerts/rules/{rule_id}` |
| `get_alert_history` | `limit` (1-50, default 20), `rule_id`, `kind` | `GET /api/notifications` |

## Rule kinds and their required fields

- `graduation`: `target_mint` or `target_agent`, both optional.
- `price_above` and `price_below`: `target_mint` and `threshold` (USD market cap) are required.
- `whale_buy`: `target_mint` and `threshold` (minimum buy size in SOL) are required.
- `new_mint`: `target_agent` (a three.ws agent UUID) is required, and `target_mint` is forbidden.

Delivery: `deliver_in_app` defaults to true. `webhook_url` must be https, and the response includes a generated `webhook_secret` for verifying the `webhook-signature` header. `telegram_chat` is a numeric chat id or an `@username` of 4-64 characters. `cooldown_seconds` runs 5-86400, default 300. An account holds at most 50 rules. `create_alert_rule` is not idempotent, so each call adds a rule.

## Worked example

Request: "Tell me in-app and on Telegram when this coin passes a $500k market cap."

Call `create_alert_rule` with `{ "kind": "price_above", "target_mint": "<base58 mint>", "threshold": 500000, "telegram_chat": "@mychat", "label": "500k cap" }`. Then call `list_alert_rules` to confirm it exists.

## Notes

- Run `list_alert_rules` before creating, so you do not add duplicates.
- `delete_alert_rule` is permanent and removes the rule's delivery log. Confirm with the user first.
- Alerts are monitoring only. They never trade, sign or spend.
