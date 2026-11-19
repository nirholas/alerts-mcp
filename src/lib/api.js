// Real HTTP access to the three.ws API. No mocks, no fixtures — every call is a
// live request to THREE_WS_BASE. Account-scoped calls (`auth: true`) attach the
// session cookie (THREE_WS_SESSION as `__Host-sid`) and fail fast with a clear
// message when it is absent. State-changing calls (POST/PATCH/DELETE) first
// fetch a one-time CSRF token from /api/csrf-token and echo it in the
// `X-CSRF-Token` header — the same double-submit flow the website uses. Errors
// are normalized into a single shape so tool handlers can surface a clean
// message + status to the MCP client.
//
// Reads (GET, including the CSRF fetch) are retried with exponential backoff on
// network errors, timeouts, 429 and 502/503/504. Writes are never retried:
// create_alert_rule is not idempotent and each CSRF token is single-use, so a
// blind retry could create a duplicate rule.

import {
	THREE_WS_BASE, HTTP_TIMEOUT_MS, USER_AGENT, THREE_WS_SESSION, isValidSessionToken,
} from '../config.js';

const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

/** Retry policy for idempotent reads. Exported so tests can shrink the delays. */
export const retryPolicy = {
	attempts: 3,
	baseDelayMs: 300,
	maxDelayMs: 5_000,
	/** @param {number} ms */
	sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/**
 * Call a three.ws HTTP endpoint and return its parsed JSON body.
 *
 * @param {string} path  Endpoint path beginning with `/` (e.g. `/api/alerts/rules`).
 * @param {{ method?: string, query?: Record<string, unknown>, body?: unknown, auth?: boolean }} [opts]
 *   `auth: true` attaches the session cookie and requires THREE_WS_SESSION; for a
 *   write method it also obtains and sends a CSRF token.
 * @returns {Promise<any>} Parsed JSON response.
 * @throws {Error} with `.code` ('no_session' | 'bad_session' | 'csrf_unavailable' | 'timeout' |
 *   'network_error' | 'upstream_error' | 'bad_response'), and on upstream errors `.status` + `.body`.
 */
export async function apiRequest(path, { method = 'GET', query, body, auth = false } = {}) {
	if (auth && !THREE_WS_SESSION) {
		throw Object.assign(
			new Error(
				`${path} is account-scoped and needs your three.ws session. Set THREE_WS_SESSION to the ` +
					'value of your `__Host-sid` cookie (copy it from a signed-in three.ws browser session).',
			),
			{ code: 'no_session', status: 401 },
		);
	}
	if (auth && !isValidSessionToken(THREE_WS_SESSION)) {
		throw Object.assign(
			new Error(
				'THREE_WS_SESSION contains characters a cookie value cannot hold (spaces, quotes, commas, ' +
					'semicolons or backslashes). Copy only the value of the `__Host-sid` cookie.',
			),
			{ code: 'bad_session', status: 401 },
		);
	}

	// State-changing calls must carry a one-time CSRF token bound to the session.
	let csrfToken;
	if (auth && WRITE_METHODS.has(method)) {
		csrfToken = await fetchCsrfToken();
	}

	const req = { method, query, body, auth, csrfToken };
	return WRITE_METHODS.has(method) ? sendRequest(path, req) : withRetry(() => sendRequest(path, req));
}

/** Obtain a fresh single-use CSRF token for the current session. */
async function fetchCsrfToken() {
	const data = await withRetry(() => sendRequest('/api/csrf-token', { method: 'GET', auth: true }));
	const token = data?.data?.token;
	if (!token || typeof token !== 'string') {
		throw Object.assign(new Error('three.ws did not return a CSRF token — is your session valid?'), {
			code: 'csrf_unavailable',
			status: 502,
		});
	}
	return token;
}

/** @param {any} err */
function isRetryable(err) {
	if (err?.code === 'timeout' || err?.code === 'network_error') return true;
	return err?.code === 'upstream_error' && RETRYABLE_STATUS.has(err.status);
}

/**
 * Run `fn`, retrying transient failures with capped exponential backoff and
 * full jitter. A Retry-After hint from a 429/503 is honored up to maxDelayMs.
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
async function withRetry(fn) {
	for (let attempt = 1; ; attempt++) {
		try {
			return await fn();
		} catch (err) {
			if (attempt >= retryPolicy.attempts || !isRetryable(err)) throw err;
			const backoff = Math.min(retryPolicy.maxDelayMs, retryPolicy.baseDelayMs * 2 ** (attempt - 1));
			const hinted = Number.isFinite(err?.retryAfterMs) ? Math.min(err.retryAfterMs, retryPolicy.maxDelayMs) : 0;
			await retryPolicy.sleep(Math.max(hinted, Math.random() * backoff));
		}
	}
}

/** Retry-After as milliseconds (delta-seconds or HTTP date), or undefined. */
function retryAfterMs(res) {
	const raw = res.headers?.get?.('retry-after');
	if (!raw) return undefined;
	const secs = Number(raw);
	if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
	const at = Date.parse(raw);
	return Number.isFinite(at) ? Math.max(0, at - Date.now()) : undefined;
}

/**
 * The single underlying HTTP client. All requests — reads, the CSRF fetch, and
 * writes — flow through here so auth, timeout, and error normalization live in
 * exactly one place. The timeout covers the whole exchange, body included.
 *
 * @param {string} path
 * @param {{ method?: string, query?: Record<string, unknown>, body?: unknown, auth?: boolean, csrfToken?: string }} [opts]
 */
async function sendRequest(path, { method = 'GET', query, body, auth = false, csrfToken } = {}) {
	const url = new URL(`${THREE_WS_BASE}${path}`);
	if (query) {
		for (const [key, value] of Object.entries(query)) {
			if (value === undefined || value === null || value === '') continue;
			url.searchParams.set(key, String(value));
		}
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

	let res;
	let text;
	try {
		res = await fetch(url, {
			method,
			headers: {
				accept: 'application/json',
				'user-agent': USER_AGENT,
				...(auth && THREE_WS_SESSION ? { cookie: `__Host-sid=${THREE_WS_SESSION}` } : {}),
				...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
				...(body !== undefined ? { 'content-type': 'application/json' } : {}),
			},
			body: body !== undefined ? JSON.stringify(body) : undefined,
			signal: controller.signal,
		});
		text = await res.text();
	} catch (err) {
		if (err?.name === 'AbortError') {
			throw Object.assign(new Error(`three.ws ${path} timed out after ${HTTP_TIMEOUT_MS}ms`), {
				code: 'timeout',
			});
		}
		throw Object.assign(new Error(`three.ws ${path} request failed: ${err?.message || err}`), {
			code: 'network_error',
		});
	} finally {
		clearTimeout(timer);
	}

	let data;
	let parsed = true;
	try {
		data = text ? JSON.parse(text) : {};
	} catch {
		parsed = false;
		data = { raw: text.slice(0, 500) };
	}

	if (!res.ok) {
		const message = data?.message || data?.error || `three.ws ${path} returned HTTP ${res.status}`;
		throw Object.assign(new Error(message), {
			code: 'upstream_error',
			status: res.status,
			body: data,
			retryAfterMs: retryAfterMs(res),
		});
	}
	// A 2xx that is not JSON (a captive portal, a proxy error page) must not be
	// read as "no rules" or "no alerts".
	if (!parsed || data === null || typeof data !== 'object') {
		throw Object.assign(new Error(`three.ws ${path} returned a non-JSON response`), {
			code: 'bad_response',
			status: res.status,
			body: data,
		});
	}
	return data;
}
