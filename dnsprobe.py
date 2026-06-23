#!/usr/bin/env python3
"""dnsprobe — DNS reconnaissance over DNS-over-HTTPS.

Queries A, AAAA, MX, NS, TXT, CNAME, and SOA records for a domain using Google
DoH (no resolver libraries needed), and can probe a built-in list of common
subdomains. Useful for the recon phase of an authorized assessment.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from typing import Optional

__version__ = "1.0.0"

DOH_URL = "https://dns.google/resolve"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "imap", "pop", "ftp", "webmail", "ns1", "ns2",
    "api", "dev", "staging", "test", "stage", "beta", "admin", "portal",
    "vpn", "remote", "gateway", "cpanel", "git", "gitlab", "jenkins",
    "app", "apps", "dashboard", "internal", "intranet", "cdn", "static",
    "assets", "media", "img", "blog", "shop", "store", "secure", "login",
    "auth", "sso", "status", "monitor", "grafana", "kibana", "proxy",
]


class Colors:
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for n in ("GREEN", "CYAN", "DIM", "BOLD", "RESET"):
            setattr(cls, n, "")


def doh_query(name: str, rtype: str, timeout: float) -> list[str]:
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    req = urllib.request.Request(
        f"{DOH_URL}?{params}",
        headers={"User-Agent": f"dnsprobe/{__version__}", "Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return []
    return [a["data"] for a in data.get("Answer", []) if "data" in a]


def records(domain: str, timeout: float) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        answers = doh_query(domain, rtype, timeout)
        if answers:
            out[rtype] = answers
    return out


def probe_subdomains(domain: str, names: list[str], timeout: float) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for sub in names:
        fqdn = f"{sub}.{domain}"
        answers = doh_query(fqdn, "A", timeout)
        if answers:
            found[fqdn] = answers
    return found


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="dnsprobe", description=__doc__.splitlines()[0])
    p.add_argument("domain")
    p.add_argument("-s", "--subdomains", action="store_true",
                   help="probe common subdomains")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if args.no_color or args.json or not sys.stdout.isatty():
        Colors.disable()
    c = Colors

    domain = args.domain.strip().lower().strip(".")
    recs = records(domain, args.timeout)
    subs = probe_subdomains(domain, COMMON_SUBDOMAINS, args.timeout) if args.subdomains else {}

    if args.json:
        print(json.dumps({"domain": domain, "records": recs, "subdomains": subs}, indent=2))
        return 0 if recs else 1

    if not recs:
        print(f"no DNS records resolved for {domain}")
        return 1

    print(f"{c.BOLD}dnsprobe{c.RESET} {c.DIM}{domain}{c.RESET}\n")
    for rtype in RECORD_TYPES:
        if rtype in recs:
            print(f"  {c.CYAN}{c.BOLD}{rtype}{c.RESET}")
            for value in recs[rtype]:
                print(f"    {value}")
            print()

    if args.subdomains:
        print(f"  {c.GREEN}{c.BOLD}subdomains{c.RESET} "
              f"{c.DIM}({len(subs)} of {len(COMMON_SUBDOMAINS)} resolved){c.RESET}")
        for fqdn in sorted(subs):
            print(f"    {fqdn} {c.DIM}-> {', '.join(subs[fqdn])}{c.RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
