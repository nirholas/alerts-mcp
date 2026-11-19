// SSRF screening for alert-rule webhook URLs. Pure functions plus an injected
// DNS resolver: nothing here touches the network.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assertPublicWebhookUrl, isNonPublicIp, webhookUrlProblem } from '../src/lib/webhook-url.js';
import { webhookUrl } from '../src/lib/schemas.js';

const noDns = async () => {
	throw new Error('DNS must not be consulted for this case');
};

test('non-public IPv4 literals are rejected, public ones pass', () => {
	for (const ip of [
		'0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '127.255.255.254', '169.254.169.254',
		'172.16.0.1', '172.31.255.255', '192.0.0.8', '192.0.2.1', '192.168.1.1', '198.18.0.1',
		'198.51.100.7', '203.0.113.9', '224.0.0.1', '255.255.255.255',
	]) {
		assert.equal(isNonPublicIp(ip), true, `${ip} should be non-public`);
	}
	for (const ip of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '100.128.0.1', '192.169.0.1']) {
		assert.equal(isNonPublicIp(ip), false, `${ip} should be public`);
	}
});

test('non-public IPv6 literals, including embedded IPv4, are rejected', () => {
	for (const ip of [
		'::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'fe80::1%eth0', 'ff02::1', '2001:db8::1',
		'::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe',
		'2002:a9fe:a9fe::1', '::127.0.0.1',
	]) {
		assert.equal(isNonPublicIp(ip), true, `${ip} should be non-public`);
	}
	for (const ip of ['2606:4700:4700::1111', '::ffff:1.1.1.1', '64:ff9b::808:808']) {
		assert.equal(isNonPublicIp(ip), false, `${ip} should be public`);
	}
});

test('URL-level checks: scheme, credentials, private hostnames and IP literal spellings', () => {
	const bad = [
		'http://hooks.example.com/x',
		'ftp://hooks.example.com/x',
		'https://user:pass@hooks.example.com/x',
		'https://localhost/x',
		'https://api.localhost/x',
		'https://printer.local/x',
		'https://metadata.google.internal/computeMetadata/v1/',
		'https://intranet/x',
		'https://127.0.0.1/x',
		'https://2130706433/x', // decimal 127.0.0.1
		'https://0x7f.0.0.1/x', // hex octet
		'https://0177.0.0.1/x', // octal octet
		'https://169.254.169.254/latest/meta-data/',
		'https://[::1]/x',
		'https://[::ffff:10.0.0.1]/x',
		'https://[fe80::1]/x',
		'not a url',
	];
	for (const u of bad) assert.ok(webhookUrlProblem(u), `${u} should be rejected`);

	for (const u of ['https://hooks.example.com/pump', 'https://1.1.1.1/hook', 'https://[2606:4700:4700::1111]/h', 'https://hooks.example.com.:8443/x']) {
		assert.equal(webhookUrlProblem(u), null, `${u} should pass`);
	}
});

test('the zod schema reports the same problems', () => {
	const schema = webhookUrl();
	assert.equal(schema.safeParse('https://hooks.example.com/pump').success, true);
	const res = schema.safeParse('https://169.254.169.254/latest/meta-data/');
	assert.equal(res.success, false);
	assert.match(res.error.issues[0].message, /non-public/);
});

test('a hostname resolving to a private address is rejected (DNS-aware check)', async () => {
	const lookup = async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.5', family: 4 }];
	await assert.rejects(assertPublicWebhookUrl('https://rebind.example.com/x', { lookup }), (err) => {
		assert.equal(err.code, 'invalid_webhook_url');
		assert.match(err.message, /10\.0\.0\.5/);
		return true;
	});
});

test('a hostname resolving to IPv4-mapped loopback is rejected', async () => {
	const lookup = async () => [{ address: '::ffff:127.0.0.1', family: 6 }];
	await assert.rejects(assertPublicWebhookUrl('https://sneaky.example.com/x', { lookup }), /non-public/);
});

test('public answers pass; a failed lookup defers to the backend check', async () => {
	await assertPublicWebhookUrl('https://hooks.example.com/x', {
		lookup: async () => [{ address: '93.184.216.34', family: 4 }],
	});
	await assertPublicWebhookUrl('https://hooks.example.com/x', {
		lookup: async () => {
			throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
		},
	});
});

test('IP-literal URLs never trigger a DNS lookup', async () => {
	await assertPublicWebhookUrl('https://1.1.1.1/hook', { lookup: noDns });
	await assert.rejects(assertPublicWebhookUrl('https://10.0.0.1/hook', { lookup: noDns }), /non-public/);
});

test('labels may not carry control characters or line breaks', async () => {
	const { label } = await import('../src/lib/schemas.js');
	assert.equal(label().safeParse('Whale watch: $THREE').success, true);
	assert.equal(label().safeParse('line one\nline two').success, false);
	assert.equal(label().safeParse('bell\u0007').success, false);
});
