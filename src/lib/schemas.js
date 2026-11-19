// Input schemas shared by the alert-rule tools, so create_alert_rule,
// update_alert_rule and get_alert_history validate the same fields the same way.

import { z } from 'zod';

import { webhookUrlProblem } from './webhook-url.js';

export const ALERT_KINDS = /** @type {const} */ (['graduation', 'price_above', 'price_below', 'whale_buy', 'new_mint']);

const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
// C0/C1 control characters (newlines included). A label is echoed into
// Telegram and webhook payloads, so it stays on one printable line.
const CONTROL_CHARS_RE = /\p{Cc}/u;

export const kind = () => z.enum(ALERT_KINDS);

export const mint = () => z.string().regex(BASE58_RE, 'must be a base58 Solana mint address');

export const agentId = () => z.string().uuid();

export const ruleId = () => z.string().uuid();

export const threshold = () => z.number().positive().finite();

export const webhookUrl = () =>
	z
		.string()
		.max(2048)
		.superRefine((value, ctx) => {
			const problem = webhookUrlProblem(value);
			if (problem) ctx.addIssue({ code: 'custom', message: problem.message.replace(/^webhook_url /, '') });
		});

export const telegramChat = () =>
	z.string().regex(/^(-?\d{1,32}|@[a-zA-Z0-9_]{4,64})$/, 'numeric chat id or @username');

export const cooldownSeconds = () => z.number().int().min(5).max(86_400);

export const label = () =>
	z
		.string()
		.max(80)
		.refine((s) => !CONTROL_CHARS_RE.test(s), 'must not contain control characters or line breaks');

/**
 * Copy of `o` without the keys whose value is `undefined`, so a PATCH sends only
 * the fields the caller set (null is kept: it clears a field).
 * @template {Record<string, unknown>} T
 * @param {T} o
 * @returns {Partial<T>}
 */
export function dropUndefined(o) {
	return /** @type {Partial<T>} */ (Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)));
}
