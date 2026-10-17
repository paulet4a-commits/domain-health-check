# domain-health-check

Check a domain's **registration expiry**, **SPF**, **DMARC**, **nameservers** and **MX** records from the command line or in CI. One small Node.js script, no dependencies, no API keys.

```text
$ npx github:paulet4a-commits/domain-health-check example.com

example.com
  expiry       2027-08-13 (299d)
  spf          ok
  dmarc        ok (p=reject)
  nameservers  a.iana-servers.net, b.iana-servers.net
  mx           none
  OK       no problems found
```

## What it checks

| Check | Source | Flags |
|---|---|---|
| Registration expiry | Registry RDAP via [rdap.org](https://rdap.org) (parent domain for subdomains) | expired, or 30 days or fewer left |
| SPF | TXT record, DNS-over-HTTPS | missing (for zones and mail domains), more than one record, `+all` |
| DMARC | `_dmarc` TXT record (inherits the parent policy with `sp=` for subdomains) | missing, `p=none`, no valid policy |
| Nameservers, MX | DNS-over-HTTPS | name does not exist (NXDOMAIN) |

Lookups go to `cloudflare-dns.com` and `rdap.org`. Nothing else is contacted and nothing is stored.

## Install

Node.js 18.17 or newer.

```bash
npx github:paulet4a-commits/domain-health-check example.com example.org
# or
git clone https://github.com/paulet4a-commits/domain-health-check && cd domain-health-check
node bin/domain-health-check.mjs example.com
```

## Options

```text
--json              Print JSON instead of a table
--fail-on <rule>    Exit 1 when a finding matches: critical, warning, info,
                    or a finding kind such as dmarc_missing (comma-separated)
--file <path>       Read domains from a file, one per line (# comments allowed)
--doh <url>         DNS-over-HTTPS endpoint (default https://cloudflare-dns.com/dns-query)
--concurrency <n>   Domains checked in parallel (default 4)
```

Exit codes: `0` no matching findings, `1` a `--fail-on` rule matched, `2` usage error or invalid domain.

Finding kinds: `expiry_expired`, `expiry_soon`, `spf_missing`, `spf_multiple`, `spf_permissive`, `dmarc_missing`, `dmarc_monitoring`, `dmarc_invalid`, `no_dns`.

## Use it in CI

Fail a scheduled workflow when a domain is close to expiry or loses its email protection:

```yaml
# .github/workflows/domains.yml
on:
  schedule: [{ cron: '0 6 * * 1' }]
  workflow_dispatch:
jobs:
  domains:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npx -y github:paulet4a-commits/domain-health-check --file domains.txt --fail-on warning
```

## Use it as a library

```js
import { checkDomain } from 'domain-health-check';
const result = await checkDomain('example.com');
console.log(result.findings);
```

## Limits

- Some country-code registries do not publish an expiry date over RDAP; the result says `not published`.
- TLS certificate expiry, DKIM selectors and new hostnames from certificate-transparency logs are not checked here.
- A DNS policy is not proof of how receivers handle mail.

## Daily monitoring

This tool gives you a snapshot. If you want these checks to run every day for many domains, with email, webhook or Telegram alerts 30, 14, 7 and 1 days before domain or TLS expiry and whenever SPF, DMARC or nameservers change, see [Domain Watch](https://watch.chimeramind.com/?utm_source=github&utm_medium=readme&utm_campaign=domain-health-check). There is also a [free web version of this check](https://watch.chimeramind.com/domain-health-check?utm_source=github&utm_medium=readme&utm_campaign=domain-health-check) and a [DMARC and SPF report on the top 1,000 domains](https://watch.chimeramind.com/email-security-report-2026?utm_source=github&utm_medium=readme&utm_campaign=domain-health-check).

## License

MIT © 2026 ChimeraMiND
