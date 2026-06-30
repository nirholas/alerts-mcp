// Real HTTP access to the three.ws API. No mocks, no fixtures — every call is a
// live request to THREE_WS_BASE. Account-scoped calls (`auth: true`) attach the
// session cookie (THREE_WS_SESSION as `__Host-sid`) and fail fast with a clear
// message when it is absent. State-changing calls (POST/PATCH/DELETE) first
// fetch a one-time CSRF token from /api/csrf-token and echo it in the
// `X-CSRF-Token` header — the same double-submit flow the website uses. Errors
// are normalized into a single shape so tool handlers can surface a clean
// message + status to the MCP client.

import { THREE_WS_BASE, HTTP_TIMEOUT_MS, USER_AGENT, THREE_WS_SESSION } from '../config.js';

const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

/**
 * Call a three.ws HTTP endpoint and return its parsed JSON body.
 *
 * @param {string} path  Endpoint path beginning with `/` (e.g. `/api/alerts/rules`).
 * @param {{ method?: string, query?: Record<string, unknown>, body?: unknown, auth?: boolean }} [opts]
 *   `auth: true` attaches the session cookie and requires THREE_WS_SESSION; for a
 *   write method it also obtains and sends a CSRF token.
 * @returns {Promise<any>} Parsed JSON response.
 * @throws {Error} with `.code` ('no_session' | 'csrf_unavailable' | 'timeout' |
 *   'network_error' | 'upstream_error'), and on upstream errors `.status` + `.body`.
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

	// State-changing calls must carry a one-time CSRF token bound to the session.
	let csrfToken;
	if (auth && WRITE_METHODS.has(method)) {
		csrfToken = await fetchCsrfToken();
	}

	return sendRequest(path, { method, query, body, auth, csrfToken });
}

/** Obtain a fresh single-use CSRF token for the current session. */
async function fetchCsrfToken() {
	const data = await sendRequest('/api/csrf-token', { method: 'GET', auth: true });
	const token = data?.data?.token;
	if (!token || typeof token !== 'string') {
		throw Object.assign(new Error('three.ws did not return a CSRF token — is your session valid?'), {
			code: 'csrf_unavailable',
			status: 502,
		});
	}
	return token;
}

/** The single underlying HTTP client. All requests — reads, the CSRF fetch, and
 *  writes — flow through here so auth, timeout, and error normalization live in
 *  exactly one place. */
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
	} catch (err) {
		clearTimeout(timer);
		if (err?.name === 'AbortError') {
			throw Object.assign(new Error(`three.ws ${path} timed out after ${HTTP_TIMEOUT_MS}ms`), {
				code: 'timeout',
			});
		}
		throw Object.assign(new Error(`three.ws ${path} request failed: ${err?.message || err}`), {
			code: 'network_error',
		});
	}
	clearTimeout(timer);

	const text = await res.text();
	let data;
	try {
		data = text ? JSON.parse(text) : {};
	} catch {
		data = { raw: text };
	}

	if (!res.ok) {
		const message = data?.message || data?.error || `three.ws ${path} returned HTTP ${res.status}`;
		throw Object.assign(new Error(message), { code: 'upstream_error', status: res.status, body: data });
	}
	return data;
}
