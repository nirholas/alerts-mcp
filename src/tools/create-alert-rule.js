// `create_alert_rule` — define a new pump.fun monitoring rule on the
// authenticated account. Write (appends a new rule — NOT idempotent: calling
// twice creates two rules).
//
// Wraps POST /api/alerts/rules. Cross-field requirements are enforced by the API
// and surfaced verbatim on a 400; the descriptions below state them so an agent
// gets the combination right the first time.

import { z } from 'zod';

import { apiRequest } from '../lib/api.js';
import {
	agentId, cooldownSeconds, dropUndefined, kind, label, mint, telegramChat, threshold, webhookUrl,
} from '../lib/schemas.js';
import { shapeRule } from '../lib/shapes.js';
import { assertPublicWebhookUrl } from '../lib/webhook-url.js';

export const def = {
	name: 'create_alert_rule',
	title: 'Create a pump.fun alert rule',
	annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
	description:
		'Create a pump.fun alert rule on the authenticated three.ws account. The pumpfun-monitor cron ' +
		'evaluates it against the live event stream and delivers across the channels you enable, so it ' +
		'fires across devices with no dashboard open. NOT idempotent — each call adds a new rule (max 50 ' +
		'per account). Targeting by kind: `graduation` is global or scoped to target_mint OR target_agent; ' +
		'`price_above` / `price_below` / `whale_buy` require target_mint; `new_mint` requires target_agent. ' +
		'`threshold` is required for the price/whale kinds — USD market cap for price_above/price_below, ' +
		'minimum buy size in SOL for whale_buy. At least one delivery channel must be on (deliver_in_app ' +
		'defaults true; webhook_url must be https and gets a generated webhook_secret for signature ' +
		'verification; telegram_chat is a numeric chat id or @username). Any mint you pass is runtime ' +
		'input; three.ws promotes only $THREE. Returns the created rule. Requires THREE_WS_SESSION. ' +
		'Use this to have three.ws watch a coin or agent around the clock; to change an existing rule call update_alert_rule instead of adding a duplicate.',
	inputSchema: {
		kind: kind()
			.describe('Event to watch: graduation | price_above | price_below | whale_buy | new_mint.'),
		target_mint: mint()
			.optional()
			.describe('Coin mint to watch. Required for price_above/price_below/whale_buy; optional for graduation; forbidden for new_mint.'),
		target_agent: agentId()
			.optional()
			.describe('three.ws agent UUID to watch. Required for new_mint; optional for graduation; forbidden for the mint-targeted kinds.'),
		threshold: threshold()
			.optional()
			.describe('Required for price/whale kinds: USD market cap for price_above/price_below, minimum buy size in SOL for whale_buy. Ignored for graduation/new_mint.'),
		deliver_in_app: z.boolean().default(true).describe('Deliver as an in-app notification (default true).'),
		webhook_url: webhookUrl()
			.optional()
			.describe('Public HTTPS endpoint to POST a signed alert event to (private, loopback and link-local hosts are rejected). The response includes a generated webhook_secret for verifying the webhook-signature header.'),
		telegram_chat: telegramChat()
			.optional()
			.describe('Telegram numeric chat id (e.g. 123456789) or @username to deliver to via the platform bot.'),
		cooldown_seconds: cooldownSeconds()
			.default(300)
			.describe('Minimum seconds between fires for this rule (5–86400, default 300).'),
		enabled: z.boolean().default(true).describe('Whether the rule is active (default true).'),
		label: label().optional().describe('Optional human label; a default is derived from kind/target when omitted.'),
	},
	async handler(args) {
		if (args.webhook_url) await assertPublicWebhookUrl(args.webhook_url);
		const body = dropUndefined({
			kind: args.kind,
			target_mint: args.target_mint,
			target_agent: args.target_agent,
			threshold: args.threshold,
			deliver_in_app: args.deliver_in_app,
			webhook_url: args.webhook_url,
			telegram_chat: args.telegram_chat,
			cooldown_seconds: args.cooldown_seconds,
			enabled: args.enabled,
			label: args.label,
		});
		const data = await apiRequest('/api/alerts/rules', { method: 'POST', auth: true, body });
		return { ok: true, rule: shapeRule(data?.rule) };
	},
};
