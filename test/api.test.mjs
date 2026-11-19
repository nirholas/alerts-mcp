// Transport behaviour of the three.ws client: retries, timeouts and response
// validation, with fetch stubbed. A separate file (and so a separate process)
// because config.js snapshots THREE_WS_TIMEOUT_MS at import time.

import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.THREE_WS_SESSION = 'test-session-cookie';
process.env.THREE_WS_BASE = 'https://three.test';
process.env.THREE_WS_TIMEOUT_MS = '50';

const { apiRequest, retryPolicy } = await import('../src/lib/api.js');
const { parseBaseUrl, isValidSessionToken } = await import('../src/config.js');
const { def: createRule } = await import('../src/tools/create-alert-rule.js');

const sleeps = [];
retryPolicy.sleep = async (ms) => {
	sleeps.push(ms);
};

function response(body, { status = 200, headers = {} } = {}) {
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: new Headers(headers),
		text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
	};
}

function stubFetch(t, responder) {
	const calls = [];
	t.mock.method(globalThis, 'fetch', async (url, init) => {
		calls.push({ url: String(url), init });
		return responder(String(url), init, calls.length);
	});
	return calls;
}

test('a GET is retried on 503 and succeeds on the next attempt', async (t) => {
	sleeps.length = 0;
	const calls = stubFetch(t, (_u, _i, n) => (n === 1 ? response({ message: 'busy' }, { status: 503 }) : response({ rules: [] })));
	const data = await apiRequest('/api/alerts/rules', { auth: true });
	assert.deepEqual(data, { rules: [] });
	assert.equal(calls.length, 2);
	assert.equal(sleeps.length, 1);
});

test('a GET honours Retry-After (capped) on 429', async (t) => {
	sleeps.length = 0;
	stubFetch(t, (_u, _i, n) =>
		n === 1 ? response({}, { status: 429, headers: { 'retry-after': '2' } }) : response({ ok: true }),
	);
	await apiRequest('/api/alerts/rules', { auth: true });
	assert.equal(sleeps[0], 2000);
});

test('a GET gives up after the configured attempts', async (t) => {
	const calls = stubFetch(t, () => response({ message: 'down' }, { status: 502 }));
	await assert.rejects(apiRequest('/api/alerts/rules', { auth: true }), (err) => {
		assert.equal(err.code, 'upstream_error');
		assert.equal(err.status, 502);
		return true;
	});
	assert.equal(calls.length, retryPolicy.attempts);
});

test('client errors are not retried', async (t) => {
	const calls = stubFetch(t, () => response({ message: 'nope' }, { status: 404 }));
	await assert.rejects(apiRequest('/api/alerts/rules', { auth: true }), { status: 404 });
	assert.equal(calls.length, 1);
});

test('a write is never retried, even on a retryable status', async (t) => {
	const calls = stubFetch(t, (url) =>
		url.endsWith('/api/csrf-token') ? response({ data: { token: 'tok' } }) : response({ message: 'busy' }, { status: 503 }),
	);
	await assert.rejects(apiRequest('/api/alerts/rules', { method: 'POST', auth: true, body: {} }), { status: 503 });
	const posts = calls.filter((c) => c.init.method === 'POST');
	assert.equal(posts.length, 1);
});

test('the timeout also covers a stalled response body', async (t) => {
	t.mock.method(globalThis, 'fetch', async (_url, init) => ({
		ok: true,
		status: 200,
		headers: new Headers(),
		text: () =>
			new Promise((_resolve, reject) => {
				init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
			}),
	}));
	await assert.rejects(apiRequest('/api/alerts/rules', { method: 'POST', auth: false, body: {} }), { code: 'timeout' });
});

test('a 2xx that is not JSON is an error, not an empty result', async (t) => {
	stubFetch(t, () => response('<html>captive portal</html>'));
	await assert.rejects(apiRequest('/api/alerts/rules', { auth: true }), { code: 'bad_response' });
});

test('create_alert_rule refuses a private webhook before any request is sent', async (t) => {
	const calls = stubFetch(t, () => response({}));
	await assert.rejects(
		createRule.handler({ kind: 'graduation', webhook_url: 'https://169.254.169.254/latest/meta-data/' }),
		{ code: 'invalid_webhook_url' },
	);
	assert.equal(calls.length, 0);
});

test('THREE_WS_BASE must be https except for loopback', () => {
	assert.equal(parseBaseUrl('https://three.ws/'), 'https://three.ws');
	assert.equal(parseBaseUrl('https://preview.three.ws/base/'), 'https://preview.three.ws/base');
	assert.equal(parseBaseUrl('http://localhost:3000'), 'http://localhost:3000');
	assert.equal(parseBaseUrl('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
	assert.throws(() => parseBaseUrl('http://three.ws'), { code: 'bad_config' });
	assert.throws(() => parseBaseUrl('three.ws'), { code: 'bad_config' });
	assert.throws(() => parseBaseUrl('https://u:p@three.ws'), { code: 'bad_config' });
	assert.throws(() => parseBaseUrl('https://three.ws/?x=1'), { code: 'bad_config' });
});

test('a session value that could inject extra cookies is rejected', () => {
	assert.equal(isValidSessionToken('s%3Aabc.DEF-_~+/='), true);
	for (const bad of ['a;b', 'a b', 'a,b', 'a"b', 'a\\b', 'a\nb', '']) {
		assert.equal(isValidSessionToken(bad), false, JSON.stringify(bad));
	}
});
