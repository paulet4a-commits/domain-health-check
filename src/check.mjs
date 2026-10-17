// Core checks: registration expiry (RDAP), SPF, DMARC, NS and MX (DNS-over-HTTPS).
// No dependencies; uses the global fetch of Node 18+.

export const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const USER_AGENT = 'domain-health-check (+https://github.com/paulet4a-commits/domain-health-check)';
const DNS_TYPES = { NS: 2, MX: 15, TXT: 16 };
const SOON_DAYS = 30;
export const LEVELS = { info: 0, warning: 1, critical: 2 };

export function matchesFailOn(finding, rules) {
  return rules.some((r) => (r in LEVELS ? LEVELS[finding.level] >= LEVELS[r] : finding.kind === r));
}

export function normalizeDomain(input) {
  let text = String(input ?? '').trim().toLowerCase();
  if (text.includes('@')) text = text.split('@').pop();
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#:]/)[0].replace(/\.$/, '');
  if (!text || text.length > 253 || !text.includes('.')) return null;
  if (/^\d+(\.\d+){3}$/.test(text)) return null;
  const labels = text.split('.');
  if (labels.some((l) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]+)$/.test(labels.at(-1))) return null;
  return text;
}

const txtValue = (data) => {
  const parts = String(data).match(/"((?:[^"\\]|\\.)*)"/g);
  return parts ? parts.map((p) => p.slice(1, -1).replace(/\\(.)/g, '$1')).join('') : String(data);
};

export function evaluateSpf(records) {
  const spf = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (!spf.length) return { status: 'missing' };
  if (spf.length > 1) return { status: 'multiple', records: spf };
  const record = spf[0].trim();
  if (/(^|\s)\+?all(\s|$)/i.test(record) && !/(^|\s)[-~?]all(\s|$)/i.test(record)) return { status: 'permissive', record };
  return { status: 'ok', record };
}

export function evaluateDmarc(records, { inherited = false } = {}) {
  const dmarc = records.filter((r) => /^v=DMARC1(\s*;|\s*$)/i.test(r.trim()));
  if (!dmarc.length) return { status: 'missing' };
  const record = dmarc[0].trim();
  const tag = (name) => new RegExp(`(?:^|;)\\s*${name}\\s*=\\s*(none|quarantine|reject)\\s*(?:;|$)`, 'i').exec(record)?.[1]?.toLowerCase();
  const policy = (inherited && tag('sp')) || tag('p');
  if (!policy) return { status: 'invalid', record };
  return { status: policy === 'none' ? 'monitoring' : 'ok', policy, record };
}

export function parseRdapExpiry(rdap, now = new Date()) {
  const event = (rdap?.events || []).find((e) => e?.eventAction === 'expiration' && e.eventDate);
  const time = event ? Date.parse(event.eventDate) : NaN;
  if (!Number.isFinite(time)) return { status: 'unavailable' };
  const days = Math.floor((time - now.getTime()) / 86400000);
  return { status: days < 0 ? 'expired' : days <= SOON_DAYS ? 'soon' : 'ok', expiresAt: event.eventDate, daysLeft: days };
}

async function dns(fetchImpl, endpoint, name, type, timeoutMs) {
  const res = await fetchImpl(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { accept: 'application/dns-json', 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`DNS HTTP ${res.status}`);
  const body = await res.json();
  if (body.Status !== 0) return Object.assign([], { nxdomain: body.Status === 3 });
  return (body.Answer || []).filter((a) => a.type == null || a.type === DNS_TYPES[type]).map((a) => String(a.data));
}

async function rdap(fetchImpl, domain, now, timeoutMs) {
  const labels = domain.split('.');
  const names = labels.length > 2 ? [domain, labels.slice(1).join('.')] : [domain];
  for (const name of names) {
    const res = await fetchImpl(`https://rdap.org/domain/${name}`, {
      headers: { accept: 'application/rdap+json', 'user-agent': USER_AGENT }, redirect: 'follow', signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 404) continue;
    if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
    return parseRdapExpiry(await res.json(), now);
  }
  return { status: 'unavailable' };
}

const hostName = (v) => v.trim().split(/\s+/).pop().replace(/\.$/, '').toLowerCase();

export function findings({ expiry, spf, dmarc, nameservers, mx }, { nxdomain = false } = {}) {
  if (nxdomain) return [{ kind: 'no_dns', level: 'critical', text: 'The name does not exist in DNS.' }];
  const out = [];
  const date = expiry.expiresAt?.slice(0, 10);
  if (expiry.status === 'expired') out.push({ kind: 'expiry_expired', level: 'critical', text: `Registration expired on ${date}.` });
  if (expiry.status === 'soon') out.push({ kind: 'expiry_soon', level: 'warning', text: `Registration expires in ${expiry.daysLeft} days (${date}).` });
  const zoneOrMail = Boolean(nameservers?.length || mx?.length);
  if (spf.status === 'missing' && zoneOrMail) out.push({ kind: 'spf_missing', level: 'warning', text: 'No SPF record.' });
  if (spf.status === 'multiple') out.push({ kind: 'spf_multiple', level: 'warning', text: 'More than one SPF record; receivers treat this as an error.' });
  if (spf.status === 'permissive') out.push({ kind: 'spf_permissive', level: 'critical', text: 'SPF ends in +all: any server may send as this domain.' });
  if (dmarc.status === 'missing') out.push({ kind: 'dmarc_missing', level: 'warning', text: 'No DMARC record.' });
  if (dmarc.status === 'monitoring') out.push({ kind: 'dmarc_monitoring', level: 'info', text: 'DMARC p=none: reports only, spoofed mail is still delivered.' });
  if (dmarc.status === 'invalid') out.push({ kind: 'dmarc_invalid', level: 'warning', text: 'DMARC record has no valid p= policy.' });
  return out;
}

export async function checkDomain(input, { fetchImpl = fetch, doh = DEFAULT_DOH, now = new Date(), timeoutMs = 8000 } = {}) {
  const domain = normalizeDomain(input);
  if (!domain) return { input, error: 'invalid_domain' };
  const failed = { status: 'error' };
  const settle = (p, fb) => p.catch(() => fb);
  const [expiry, apexTxt, dmarcTxt, ns, mx] = await Promise.all([
    settle(rdap(fetchImpl, domain, now, timeoutMs), failed),
    settle(dns(fetchImpl, doh, domain, 'TXT', timeoutMs), null),
    settle(dns(fetchImpl, doh, '_dmarc.' + domain, 'TXT', timeoutMs), null),
    settle(dns(fetchImpl, doh, domain, 'NS', timeoutMs), null),
    settle(dns(fetchImpl, doh, domain, 'MX', timeoutMs), null),
  ]);
  let dmarc = dmarcTxt ? evaluateDmarc(dmarcTxt.map(txtValue)) : failed;
  const parent = domain.split('.').slice(1).join('.');
  if (dmarc.status === 'missing' && parent.includes('.')) {
    const parentTxt = await settle(dns(fetchImpl, doh, '_dmarc.' + parent, 'TXT', timeoutMs), null);
    const inherited = parentTxt ? evaluateDmarc(parentTxt.map(txtValue), { inherited: true }) : null;
    if (inherited && inherited.status !== 'missing') dmarc = { ...inherited, inheritedFrom: parent };
  }
  const result = {
    domain, checkedAt: now.toISOString(), expiry,
    spf: apexTxt ? evaluateSpf(apexTxt.map(txtValue)) : failed,
    dmarc,
    nameservers: ns ? ns.map(hostName) : null,
    mx: mx ? mx.map(hostName).filter(Boolean) : null,
  };
  const incomplete = [expiry === failed ? null : expiry, apexTxt, dmarcTxt, ns, mx].includes(null);
  return { ...result, incomplete, findings: findings(result, { nxdomain: ns?.nxdomain === true }) };
}
