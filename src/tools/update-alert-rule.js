// `update_alert_rule` — change an existing pump.fun alert rule on the
// authenticated account. Write, idempotent: re-applying the same patch leaves the
// rule in the same state.
//
// Wraps PATCH /api/alerts/rules/:id. Only the fields you pass change; everything
// else is left as-is. Clearable fields (target_mint, target_agent, threshold,
// webhook_url, telegram_chat, label) accept null to remove the value. The merged
// rule is re-validated by the API against its (possibly new) kind.

import { z } from 'zod';

import { apiRequest } from '../lib/api.js';
import {
	agentId, cooldownSeconds, dropUndefined, kind, label, mint, ruleId, telegramChat, threshold, webhookUrl,
} from '../lib/schemas.js';
import { shapeRule } from '../lib/shapes.js';
import { assertPublicWebhookUrl } from '../lib/webhook-url.js';

export const def = {
	name: 'update_alert_rule',
	title: 'Update a pump.fun alert rule',
	annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
	description:
		'Update an existing pump.fun alert rule by id on the authenticated three.ws account. Partial — only ' +
		'the fields you pass change. Idempotent: re-applying the same values yields the same rule. Common ' +
		'uses: flip `enabled` to pause/resume, retune `threshold`, add or swap a delivery channel, or ' +
		'change `kind` (the rule is re-validated against the new kind, and fields incompatible with it are ' +
		'cleared automatically). Pass null to clear a clearable field (target_mint, target_agent, ' +
		'threshold, webhook_url, telegram_chat, label). Removing webhook_url drops its secret; adding one ' +
		'mints a fresh webhook_secret (returned). The result must still have at least one delivery channel ' +
		'and satisfy the kind\'s targeting/threshold rules, or the API rejects it with a precise message. ' +
		'Returns the updated rule. Requires THREE_WS_SESSION. ' +
		'Use this to pause, retune, or re-route an existing rule; unlike delete_alert_rule it keeps the rule and its history.',
	inputSchema: {
		rule_id: ruleId().describe('Id of the rule to update (from list_alert_rules).'),
		kind: kind()
			.optional()
			.describe('Change the event kind. The rule is re-validated against it and incompatible fields are cleared.'),
		target_mint: mint()
			.nullable()
			.optional()
			.describe('Coin mint to watch, or null to clear. Required by price/whale kinds; forbidden for new_mint.'),
		target_agent: agentId()
			.nullable()
			.optional()
			.describe('three.ws agent UUID to watch, or null to clear. Required by new_mint; forbidden for mint-targeted kinds.'),
		threshold: threshold()
			.nullable()
			.optional()
			.describe('USD market cap (price kinds) or SOL buy size (whale_buy), or null to clear.'),
		deliver_in_app: z.boolean().optional().describe('Toggle in-app delivery.'),
		webhook_url: webhookUrl()
			.nullable()
			.optional()
			.describe('Public HTTPS endpoint for signed alert events (private, loopback and link-local hosts are rejected), or null to remove the webhook (and its secret).'),
		telegram_chat: telegramChat()
			.nullable()
			.optional()
			.describe('Telegram numeric chat id or @username, or null to remove.'),
		cooldown_seconds: cooldownSeconds()
			.optional()
			.describe('Minimum seconds between fires (5–86400).'),
		enabled: z.boolean().optional().describe('Enable or pause the rule.'),
		label: label().nullable().optional().describe('Human label, or null to fall back to the derived default.'),
	},
	async handler(args) {
		const { rule_id, ...rest } = args;
		if (rest.webhook_url) await assertPublicWebhookUrl(rest.webhook_url);
		const body = dropUndefined(rest);
		const data = await apiRequest(`/api/alerts/rules/${encodeURIComponent(rule_id)}`, {
			method: 'PATCH',
			auth: true,
			body,
		});
		return { ok: true, rule: shapeRule(data?.rule) };
	},
};
