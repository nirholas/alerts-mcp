#!/usr/bin/env node
// @three-ws/alerts-mcp — MCP server entry point.
//
// The market-monitoring control surface for an AI agent's OWN pump.fun alert
// rules over stdio:
//   • list_alert_rules   — the account's rules + live delivery health
//   • create_alert_rule  — define a new rule (write — appends)
//   • update_alert_rule  — retune / pause / re-channel a rule (write — idempotent)
//   • delete_alert_rule  — remove a rule (write — DESTRUCTIVE)
//   • get_alert_history  — the alerts that actually fired, newest first
//
// Account-scoped over the live three.ws API. Every call carries your three.ws
// session (THREE_WS_SESSION = the `__Host-sid` cookie); writes additionally fetch
// and echo a one-time CSRF token, exactly like the website. No Solana key, no
// signer — the only secret is the session token.
//
// Run standalone:
//   THREE_WS_SESSION=… node packages/alerts-mcp/src/index.js
//
// Or wire into Claude Code / Cursor — see README.md.

import { realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { def as listAlertRules } from './tools/list-alert-rules.js';
import { def as createAlertRule } from './tools/create-alert-rule.js';
import { def as updateAlertRule } from './tools/update-alert-rule.js';
import { def as deleteAlertRule } from './tools/delete-alert-rule.js';
import { def as getAlertHistory } from './tools/get-alert-history.js';

// Single source of truth for the advertised server version — package.json.
const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require('../package.json');

export const TOOLS = [
	listAlertRules,
	createAlertRule,
	updateAlertRule,
	deleteAlertRule,
	getAlertHistory,
];

/**
 * Construct a fully-registered McpServer without connecting a transport.
 * Registration is env-free, so this is safe to import from tests.
 * @returns {McpServer}
 */
export function buildServer() {
	const server = new McpServer(
		{ name: 'alerts-mcp', title: 'three.ws Alerts', version: PKG_VERSION },
		{
			capabilities: { tools: {} },
			instructions:
				'three.ws Alerts MCP — let an agent run its own pump.fun monitoring. list_alert_rules shows ' +
				'the account\'s rules with live delivery health (last fired, recent failures, recent ' +
				'per-channel outcomes). create_alert_rule defines a rule on a pump.fun event — graduation, ' +
				'price_above / price_below (USD market cap), whale_buy (SOL buy size), or new_mint (a tracked ' +
				'agent launches) — delivered in-app, to a signed HTTPS webhook, and/or to Telegram. ' +
				'update_alert_rule retunes, pauses (enabled:false), or re-channels a rule; delete_alert_rule ' +
				'removes one permanently. get_alert_history reads the alerts that actually fired, newest ' +
				'first, each with a summary and full event payload. All calls are account-scoped: set ' +
				'THREE_WS_SESSION to your `__Host-sid` cookie. Any coin in a rule is runtime input — three.ws ' +
				'promotes only $THREE.',
		},
	);

	for (const tool of TOOLS) {
		server.registerTool(
			tool.name,
			{
				title: tool.title,
				description: tool.description,
				inputSchema: tool.inputSchema,
				annotations: tool.annotations,
			},
			async (args, extra) => {
				try {
					const result = await tool.handler(args, extra);
					const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
					return { content: [{ type: 'text', text }] };
				} catch (err) {
					const payload = {
						ok: false,
						error: err?.code || 'unhandled',
						message: err?.message || String(err),
						...(err?.status ? { status: err.status } : {}),
					};
					return {
						content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
						isError: true,
					};
				}
			},
		);
	}

	return server;
}

async function main() {
	const server = buildServer();
	const transport = new StdioServerTransport();
	await server.connect(transport);
	console.error(`[alerts-mcp@${PKG_VERSION}] connected over stdio with ${TOOLS.length} tools`);
}

// Connect stdio ONLY when this file is the process entry point. Importing the
// module (tests, embedding) must not grab the transport. realpath both sides:
// npm bin shims are symlinks, so argv[1] may differ from import.meta.url.
function isProcessEntryPoint() {
	if (!process.argv[1]) return false;
	try {
		return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
	} catch {
		return false;
	}
}

if (isProcessEntryPoint()) {
	main().catch((err) => {
		console.error('[alerts-mcp] fatal:', err);
		process.exit(1);
	});
}
