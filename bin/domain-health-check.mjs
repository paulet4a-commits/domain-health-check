#!/usr/bin/env node
// domain-health-check: expiry, SPF, DMARC, NS and MX for one or more domains.
import { readFileSync } from 'node:fs';
import { checkDomain, matchesFailOn, LEVELS, DEFAULT_DOH } from '../src/check.mjs';

const HELP = `domain-health-check — registration expiry, SPF, DMARC, nameservers and MX

Usage:
  domain-health-check <domain> [domain ...] [options]
  domain-health-check --file domains.txt [options]

Options:
  --json              Print JSON instead of a table
  --fail-on <rule>    Exit 1 when a finding matches: critical, warning, info,
                      or a finding kind such as dmarc_missing (comma-separated)
  --file <path>       Read domains from a file, one per line (# comments allowed)
  --doh <url>         DNS-over-HTTPS endpoint (default ${DEFAULT_DOH})
  --concurrency <n>   Domains checked in parallel (default 4)
  -h, --help          Show this help

Exit codes: 0 no matching findings, 1 --fail-on matched, 2 usage error.
Daily monitoring with alerts: https://watch.chimeramind.com/?utm_source=github&utm_medium=cli&utm_campaign=domain-health-check`;

function parseArgs(argv) {
  const opts = { domains: [], json: false, failOn: [], doh: DEFAULT_DOH, concurrency: 4 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--fail-on') opts.failOn.push(...next().split(',').map((s) => s.trim()).filter(Boolean));
    else if (a === '--file') opts.domains.push(...readFileSync(next(), 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean));
    else if (a === '--doh') opts.doh = next();
    else if (a === '--concurrency') opts.concurrency = Math.max(1, Math.min(16, Number(next()) || 4));
    else if (a.startsWith('-')) throw new Error(`Unknown option ${a}`);
    else opts.domains.push(a);
  }
  return opts;
}

function expiryText(e) {
  if (e.status === 'error') return 'lookup failed';
  if (e.status === 'unavailable') return 'not published';
  return `${e.expiresAt.slice(0, 10)} (${e.daysLeft}d)`;
}

function printTable(results) {
  for (const r of results) {
    if (r.error) { console.log(`${r.input}: invalid domain`); continue; }
    const dmarc = r.dmarc.policy ? `${r.dmarc.status} (p=${r.dmarc.policy}${r.dmarc.inheritedFrom ? `, from ${r.dmarc.inheritedFrom}` : ''})` : r.dmarc.status;
    console.log(`\n${r.domain}${r.incomplete ? '  [some lookups failed]' : ''}`);
    console.log(`  expiry       ${expiryText(r.expiry)}`);
    console.log(`  spf          ${r.spf.status}`);
    console.log(`  dmarc        ${dmarc}`);
    console.log(`  nameservers  ${r.nameservers ? r.nameservers.join(', ') || 'none' : 'lookup failed'}`);
    console.log(`  mx           ${r.mx ? r.mx.join(', ') || 'none' : 'lookup failed'}`);
    for (const f of r.findings) console.log(`  ${f.level.toUpperCase().padEnd(8)} ${f.text}`);
    if (!r.findings.length && !r.incomplete) console.log('  OK       no problems found');
  }
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); console.error(HELP); return 2; }
  if (opts.help) { console.log(HELP); return 0; }
  if (!opts.domains.length) { console.error(HELP); return 2; }
  const bad = opts.failOn.filter((r) => !(r in LEVELS) && !/^[a-z_]+$/.test(r));
  if (bad.length) { console.error(`Invalid --fail-on rule: ${bad.join(', ')}`); return 2; }

  const results = new Array(opts.domains.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(opts.concurrency, opts.domains.length) }, async () => {
    while (next < opts.domains.length) { const i = next++; results[i] = await checkDomain(opts.domains[i], { doh: opts.doh }); }
  }));

  if (opts.json) console.log(JSON.stringify(results, null, 2)); else printTable(results);
  if (results.some((r) => r.error)) return 2;
  return results.some((r) => r.findings.some((f) => matchesFailOn(f, opts.failOn))) ? 1 : 0;
}

main().then((code) => { process.exitCode = code; });
