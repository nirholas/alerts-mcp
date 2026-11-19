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

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Validate THREE_WS_BASE. Every account-scoped call sends the session cookie to
 * this origin, so it must be https; plain http is accepted only for a loopback
 * host (local development against a self-hosted API).
 * @param {string} raw
 * @returns {string} the base URL without a trailing slash
 */
export function parseBaseUrl(raw) {
	let url;
	try {
		url = new URL(raw);
	} catch {
		throw Object.assign(new Error(`THREE_WS_BASE must be an absolute URL (got "${raw}")`), { code: 'bad_config' });
	}
	const loopback = LOOPBACK_HOSTS.has(url.hostname);
	if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
		throw Object.assign(
			new Error(`THREE_WS_BASE must use https (http is allowed only for localhost); got "${raw}"`),
			{ code: 'bad_config' },
		);
	}
	if (url.username || url.password || url.search || url.hash) {
		throw Object.assign(new Error('THREE_WS_BASE must not carry credentials, a query string or a fragment'), {
			code: 'bad_config',
		});
	}
	return url.href.replace(/\/+$/, '');
}

// Base URL of the three.ws API. Override only when self-hosting or pointing at a
// preview deployment.
export const THREE_WS_BASE = parseBaseUrl(env('THREE_WS_BASE', 'https://three.ws'));

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

// RFC 6265 cookie-octet: printable ASCII except space, DQUOTE, comma, semicolon
// and backslash. Anything else in the session value would let it smuggle extra
// cookies (or break the header), so it is rejected before any request is sent.
const COOKIE_VALUE_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$/;

/** @param {string} value */
export function isValidSessionToken(value) {
	return COOKIE_VALUE_RE.test(value);
}

// Identifies this client to the API in request logs.
export const USER_AGENT = '@three-ws/alerts-mcp';
