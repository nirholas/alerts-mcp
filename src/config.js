// Centralized env + HTTP base for the alerts MCP.
//
// This server is the account-scoped control surface for an agent's OWN pump.fun
// alert rules (/api/alerts/rules) and its fired-alert history
// (/api/notifications). Every endpoint resolves the caller from the three.ws
// session cookie, so each call carries THREE_WS_SESSION as the `__Host-sid`
// cookie — the exact value a signed-in browser holds. Writes additionally fetch
// a one-time CSRF token (GET /api/csrf-token) and echo it, mirroring the site.
// The server holds no Solana key and never signs: the only secret is the session
// token that authenticates the account.

export function env(key, fallback) {
	const v = process.env[key];
	return v !== undefined && String(v).trim() !== '' ? String(v).trim() : fallback;
}

// Base URL of the three.ws API. Override only when self-hosting or pointing at a
// preview deployment.
export const THREE_WS_BASE = env('THREE_WS_BASE', 'https://three.ws').replace(/\/+$/, '');

// Per-request timeout (ms). These are live reads/writes against the alert-rules
// store and the notification feed — generous enough to ride out a cold edge.
export const HTTP_TIMEOUT_MS = (() => {
	const raw = env('THREE_WS_TIMEOUT_MS');
	if (raw === undefined) return 20000;
	const n = Number(raw);
	if (!Number.isFinite(n) || n <= 0) {
		throw Object.assign(new Error(`THREE_WS_TIMEOUT_MS must be a positive number (got "${raw}")`), {
			code: 'bad_config',
		});
	}
	return n;
})();

// Session token for every account-scoped call. This is the value of the
// `__Host-sid` cookie from a signed-in three.ws browser session; the API reads
// it to resolve the calling user and scope every rule and alert to that account.
// Read lazily (empty default) so importing the module — and therefore
// buildServer() in the offline tests — never requires it; tools throw a clear
// `no_session` at call time when it is absent. Treat like a password.
export const THREE_WS_SESSION = env('THREE_WS_SESSION', '');

// Identifies this client to the API in request logs.
export const USER_AGENT = '@three-ws/alerts-mcp';
