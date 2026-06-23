# dnsprobe

DNS reconnaissance over DNS-over-HTTPS. Resolves A, AAAA, MX, NS, TXT, CNAME,
and SOA records for a domain through Google DoH, and optionally probes a
built-in list of common subdomains. No resolver libraries required.

For the recon phase of assessments you are authorized to run.

## Usage

```bash
python dnsprobe.py example.com
python dnsprobe.py example.com --subdomains
python dnsprobe.py example.com --json
```

## Example

```
$ python dnsprobe.py github.com

dnsprobe github.com

  A
    140.82.121.4
  MX
    0 github-com.mail.protection.outlook.com.
  NS
    dns1.p08.nsone.net.
    ...
  TXT
    v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ...
```

`--subdomains` resolves each name in a built-in wordlist (`www`, `mail`, `api`,
`vpn`, `admin`, `staging`, ...) and lists the ones that exist.

## How it works

```
dnsprobe.py
  doh_query        GET dns.google/resolve?name=&type= (JSON answers)
  records          query each record type
  probe_subdomains resolve <word>.<domain> for each common subdomain
```

DoH means queries go out as HTTPS to a public resolver, not as UDP/53 from your
host — convenient on restricted networks and leaves no direct DNS traffic to the
target's own nameservers for the record lookups.

## Requirements

Python 3.9+, network access. No third-party packages.

## License

MIT
