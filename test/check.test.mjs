import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain, evaluateSpf, evaluateDmarc, parseRdapExpiry, normalizeDomain, matchesFailOn } from '../src/check.mjs';

const NOW = new Date('2026-10-17T12:00:00Z');

function fakeFetch({ dns = {}, rdap = {}, nx = [] } = {}) {
  return async (url) => {
    const u = new URL(url);
    if (u.hostname === 'rdap.org') {
      const name = u.pathname.split('/').pop();
      return rdap[name] ? Response.json(rdap[name]) : new Response('', { status: 404 });
    }
    const key = `${u.searchParams.get('type')} ${u.searchParams.get('name')}`;
    if (nx.includes(u.searchParams.get('name'))) return Response.json({ Status: 3 });
    return Response.json({ Status: 0, Answer: (dns[key] || []).map((data) => ({ data })) });
  };
}

const healthy = {
  dns: {
    'TXT example.com': ['"v=spf1 include:_spf.example.net -all"'],
    'TXT _dmarc.example.com': ['"v=DMARC1; p=reject"'],
    'NS example.com': ['ns1.example.net.'],
    'MX example.com': ['10 mx.example.com.'],
  },
  rdap: { 'example.com': { events: [{ eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }] } },
};

test('normalizes URLs, emails and www-less input; rejects junk', () => {
  assert.equal(normalizeDomain('https://Example.com/path?x=1'), 'example.com');
  assert.equal(normalizeDomain('ops@example.com'), 'example.com');
  for (const bad of ['', 'localhost', '10.0.0.1', 'ex ample.com', 'example.123']) assert.equal(normalizeDomain(bad), null);
});

test('SPF evaluation', () => {
  assert.equal(evaluateSpf([]).status, 'missing');
  assert.equal(evaluateSpf(['v=spf1 -all', 'v=spf1 ~all']).status, 'multiple');
  assert.equal(evaluateSpf(['v=spf1 +all']).status, 'permissive');
  assert.equal(evaluateSpf(['google-site-verification=x', 'v=spf1 ~all']).status, 'ok');
});

test('DMARC evaluation, including sp= for inherited policies', () => {
  assert.equal(evaluateDmarc([]).status, 'missing');
  assert.deepEqual(evaluateDmarc(['v=DMARC1; p=none']).status, 'monitoring');
  assert.equal(evaluateDmarc(['v=DMARC1; rua=mailto:a@b.c']).status, 'invalid');
  assert.equal(evaluateDmarc(['v=DMARC1; p=none; sp=reject'], { inherited: true }).policy, 'reject');
});

test('RDAP expiry classification', () => {
  assert.equal(parseRdapExpiry(healthy.rdap['example.com'], NOW).daysLeft, 299);
  assert.equal(parseRdapExpiry({ events: [{ eventAction: 'expiration', eventDate: '2026-10-30T00:00:00Z' }] }, NOW).status, 'soon');
  assert.equal(parseRdapExpiry({ events: [] }, NOW).status, 'unavailable');
});

test('healthy domain has no findings', async () => {
  const r = await checkDomain('example.com', { fetchImpl: fakeFetch(healthy), now: NOW });
  assert.equal(r.domain, 'example.com');
  assert.deepEqual(r.findings, []);
  assert.equal(r.incomplete, false);
});

test('weak domain lists findings in a stable order', async () => {
  const r = await checkDomain('weak.com', { now: NOW, fetchImpl: fakeFetch({
    dns: { 'NS weak.com': ['a.ns.'], 'TXT _dmarc.weak.com': ['"v=DMARC1; p=none"'] },
    rdap: { 'weak.com': { events: [{ eventAction: 'expiration', eventDate: '2026-10-25T00:00:00Z' }] } },
  }) });
  assert.deepEqual(r.findings.map((f) => f.kind), ['expiry_soon', 'spf_missing', 'dmarc_monitoring']);
});

test('subdomain inherits the parent DMARC policy and plain hostnames need no SPF', async () => {
  const r = await checkDomain('app.example.com', { now: NOW, fetchImpl: fakeFetch({ dns: { 'TXT _dmarc.example.com': ['"v=DMARC1; p=quarantine"'] }, rdap: healthy.rdap }) });
  assert.equal(r.dmarc.inheritedFrom, 'example.com');
  assert.deepEqual(r.findings, []);
});

test('NXDOMAIN reports only that the name does not exist', async () => {
  const r = await checkDomain('gone.example', { now: NOW, fetchImpl: fakeFetch({ nx: ['gone.example', '_dmarc.gone.example'] }) });
  assert.deepEqual(r.findings.map((f) => f.kind), ['no_dns']);
});

test('--fail-on matches by level threshold or by kind', () => {
  const warn = { kind: 'dmarc_missing', level: 'warning' };
  const info = { kind: 'dmarc_monitoring', level: 'info' };
  assert.equal(matchesFailOn(warn, ['warning']), true);
  assert.equal(matchesFailOn(info, ['warning']), false);
  assert.equal(matchesFailOn(info, ['dmarc_monitoring']), true);
  assert.equal(matchesFailOn(warn, ['critical']), false);
});
