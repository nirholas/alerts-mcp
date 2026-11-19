// Client-side screening of alert-rule webhook URLs.
//
// The three.ws backend delivers webhooks, so it is the authoritative SSRF
// boundary: it has to resolve the host and connect to the address it checked,
// which is the only defence against DNS rebinding. This module is the cheap
// first filter, so an agent gets a precise error before a rule that could
// never pass the backend is created. It rejects:
//   - anything other than https, and URLs carrying credentials;
//   - hostnames that only make sense inside a private network (localhost,
//     *.local, *.internal, cloud metadata names, ...);
//   - IP literals in loopback, private, link-local, CGNAT, multicast,
//     documentation and other non-routable ranges, including IPv4 addresses
//     embedded in IPv6 (mapped, NAT64, 6to4);
//   - hostnames whose DNS answer contains such an address.
// The WHATWG URL parser canonicalises IPv4 forms such as 2130706433, 0x7f.1 or
// 0177.0.0.1 to dotted decimal before these checks run.

import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

/** @type {Array<[string, number]>} */
const BLOCKED_V4 = [
	['0.0.0.0', 8], // "this" network
	['10.0.0.0', 8], // private
	['100.64.0.0', 10], // carrier-grade NAT
	['127.0.0.0', 8], // loopback
	['169.254.0.0', 16], // link-local, cloud metadata (169.254.169.254)
	['172.16.0.0', 12], // private
	['192.0.0.0', 24], // IETF protocol assignments
	['192.0.2.0', 24], // documentation
	['192.88.99.0', 24], // 6to4 relay anycast
	['192.168.0.0', 16], // private
	['198.18.0.0', 15], // benchmarking
	['198.51.100.0', 24], // documentation
	['203.0.113.0', 24], // documentation
	['224.0.0.0', 4], // multicast
	['240.0.0.0', 4], // reserved, broadcast
];

/** @type {Array<[string, number]>} */
const BLOCKED_V6 = [
	['::', 128], // unspecified
	['::1', 128], // loopback
	['100::', 64], // discard
	['2001:db8::', 32], // documentation
	['fc00::', 7], // unique local
	['fe80::', 10], // link-local
	['fec0::', 10], // deprecated site-local
	['ff00::', 8], // multicast
];

const blockList = new BlockList();
for (const [net, prefix] of BLOCKED_V4) blockList.addSubnet(net, prefix, 'ipv4');
for (const [net, prefix] of BLOCKED_V6) blockList.addSubnet(net, prefix, 'ipv6');

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata', 'metadata.google.internal', 'instance-data']);
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.intranet', '.lan', '.home.arpa', '.corp'];

/** Expand an IPv6 literal to its eight 16-bit groups, or null if malformed. */
function ipv6Groups(addr) {
	let a = addr;
	// A trailing dotted IPv4 (::ffff:1.2.3.4) becomes two hex groups.
	const v4 = a.match(/(\d+\.\d+\.\d+\.\d+)$/);
	if (v4) {
		const o = v4[1].split('.').map(Number);
		a = `${a.slice(0, -v4[1].length)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
	}
	const halves = a.split('::');
	if (halves.length > 2) return null;
	const head = halves[0] ? halves[0].split(':') : [];
	const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
	const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
	const groups = [...head, ...Array(Math.max(0, fill)).fill('0'), ...tail].map((g) => parseInt(g, 16));
	return groups.length === 8 && groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : null;
}

const v4FromGroups = (hi, lo) => `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;

/** The IPv4 address an IPv6 address carries (mapped, compatible, NAT64, 6to4), if any. */
function embeddedIpv4(addr) {
	const g = ipv6Groups(addr);
	if (!g) return null;
	const zeroPrefix = (n) => g.slice(0, n).every((x) => x === 0);
	if (zeroPrefix(5) && g[5] === 0xffff) return v4FromGroups(g[6], g[7]); // ::ffff:a.b.c.d
	if (zeroPrefix(6) && (g[6] || g[7] > 1)) return v4FromGroups(g[6], g[7]); // ::a.b.c.d (deprecated)
	if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4FromGroups(g[6], g[7]); // NAT64
	if (g[0] === 0x2002) return v4FromGroups(g[1], g[2]); // 6to4
	return null;
}

/**
 * True when `address` (an IPv4 or IPv6 literal, no brackets) is not a public,
 * globally routable unicast address.
 * @param {string} address
 */
export function isNonPublicIp(address) {
	const family = isIP(address);
	if (family === 4) return blockList.check(address, 'ipv4');
	if (family === 6) {
		const bare = address.split('%')[0]; // drop a zone id (fe80::1%eth0)
		if (blockList.check(bare, 'ipv6')) return true;
		const v4 = embeddedIpv4(bare);
		return v4 != null && blockList.check(v4, 'ipv4');
	}
	return false;
}

function reject(message) {
	return Object.assign(new Error(`webhook_url ${message}`), { code: 'invalid_webhook_url', status: 400 });
}

/**
 * Synchronous checks on the URL text alone. Returns an Error describing the
 * first problem, or null when the URL passes.
 * @param {string} raw
 * @returns {Error|null}
 */
export function webhookUrlProblem(raw) {
	let url;
	try {
		url = new URL(raw);
	} catch {
		return reject('is not a valid URL');
	}
	if (url.protocol !== 'https:') return reject('must use https');
	if (url.username || url.password) return reject('must not embed credentials');

	const host = url.hostname.toLowerCase().replace(/\.$/, '');
	if (!host) return reject('has no host');
	const literal = host.startsWith('[') ? host.slice(1, -1) : host;
	if (isIP(literal)) {
		return isNonPublicIp(literal) ? reject('points at a private, loopback or otherwise non-public address') : null;
	}
	if (!host.includes('.')) return reject('must use a fully qualified public hostname');
	if (BLOCKED_HOSTNAMES.has(host) || BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) {
		return reject('points at a private-network hostname');
	}
	return null;
}

/**
 * Full check: the URL text, then the host's DNS answer. A lookup failure does
 * not block the rule (the backend re-checks at delivery time); an answer that
 * contains a non-public address does.
 *
 * @param {string} raw
 * @param {{ lookup?: (host: string, opts: { all: true, verbatim: true }) => Promise<Array<{ address: string }>> }} [deps]
 * @returns {Promise<void>}
 * @throws {Error} with `.code = 'invalid_webhook_url'`
 */
export async function assertPublicWebhookUrl(raw, { lookup = dnsLookup } = {}) {
	const problem = webhookUrlProblem(raw);
	if (problem) throw problem;
	const host = new URL(raw).hostname;
	if (isIP(host.replace(/^\[|\]$/g, ''))) return;

	let answers;
	try {
		answers = await lookup(host, { all: true, verbatim: true });
	} catch {
		return;
	}
	const bad = (answers || []).find((a) => isNonPublicIp(a.address));
	if (bad) throw reject(`host ${host} resolves to a non-public address (${bad.address})`);
}
