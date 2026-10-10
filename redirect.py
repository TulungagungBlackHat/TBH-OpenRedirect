#!/usr/bin/env python3
"""TBH-OpenRedirect v3 - Open redirect detector (authorized testing only)."""
import argparse, json, os, re, sys, time, urllib.parse

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-OpenRedirect"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-OpenRedirect v3\033[91m               ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

MARKER_HOST = "tbh-redirect-test.invalid"
PAYLOADS = [
    f"https://{MARKER_HOST}/landing",
    f"//{MARKER_HOST}/landing",
    f"/\\{MARKER_HOST}",
    f"https:%0d%0a%0d%0a//{MARKER_HOST}",
]
PARAM_CANDIDATES = ["redirect", "redir", "next", "url", "return", "returnurl", "return_to",
                    "goto", "dest", "destination", "continue", "target", "rurl", "out", "view"]

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-OpenRedirect/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if not val:
            raise SystemExit(f"[!] bad -H value: {h!r}")
        s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def inject(url, param, value):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    if param is None:
        param = next((c for c in PARAM_CANDIDATES if c in qs), next(iter(qs), "next"))
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True))), param

def target_params(url, requested):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    if requested and requested != "all":
        return [requested]
    return list(qs.keys()) or ["next"]

def location_hit(headers, status):
    loc = headers.get("Location", "")
    if status in (301, 302, 303, 307, 308) and MARKER_HOST in loc:
        return loc
    return None

def body_hit(text):
    patterns = [
        rf"window\.location\s*=\s*['\"]([^'\"]*{re.escape(MARKER_HOST)}[^'\"]*)",
        rf"location\.href\s*=\s*['\"]([^'\"]*{re.escape(MARKER_HOST)}[^'\"]*)",
        rf'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>]*{re.escape(MARKER_HOST)}[^"\'>]*)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(0)[:120]
    return None

def scan(session, url, args):
    findings = []
    params = target_params(url, args.param)
    try:
        b = session.get(url, timeout=args.timeout, allow_redirects=True)
        baseline = {"status": b.status_code, "length": len(b.text)}
    except requests.RequestException as e:
        return {"error": f"baseline failed: {e}"}

    for param in params:
        for payload in PAYLOADS:
            test_url, _ = inject(url, param, payload)
            try:
                r = session.get(test_url, timeout=args.timeout, allow_redirects=False)
            except requests.RequestException as e:
                findings.append({"param": param, "payload": payload, "error": str(e), "verdict": "error"})
                continue
            loc = location_hit(r.headers, r.status_code)
            if loc:
                findings.append({"param": param, "payload": payload, "url": test_url,
                                 "status": r.status_code, "location": loc, "verdict": "open-redirect"})
                break
            if r.status_code == 200:
                hit = body_hit(r.text)
                if hit:
                    findings.append({"param": param, "payload": payload, "url": test_url,
                                     "status": r.status_code, "vector": hit, "verdict": "open-redirect-dom"})
                    break
            if args.delay:
                time.sleep(args.delay)

    return {"tool": "TBH-OpenRedirect", "version": VERSION, "target": url,
            "baseline": baseline, "findings": findings}

def main():
    parser = argparse.ArgumentParser(description=f"TBH-OpenRedirect v{VERSION}")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--param", help="parameter name, or 'all' (default: auto-detect redirect-ish param)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--json", help="save JSON report")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-OpenRedirect {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only. Marker host is a reserved .invalid domain (no traffic).", use_color))
    print(f"[*] Scanning {args.url}")
    try:
        session = build_session(args)
    except SystemExit as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    report = scan(session, args.url, args)
    if "error" in report:
        print(color("91", f"[!] {report['error']}", use_color))
        sys.exit(2)

    vuln = 0
    for f in report["findings"]:
        if f.get("verdict") == "open-redirect":
            vuln += 1
            print(color("91", f"[!] Open redirect on {f['param']}: {f['status']} -> {f['location']}", use_color))
        elif f.get("verdict") == "open-redirect-dom":
            vuln += 1
            print(color("91", f"[!] DOM/meta redirect on {f['param']}: {f['vector'][:80]}", use_color))
        elif f.get("verdict") == "error":
            print(color("90", f"[-] {f['param']}: {f['error']}", use_color))

    if args.json:
        report["summary"] = {"open_redirect": vuln}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    if vuln:
        print(color("91", f"[!] {vuln} open redirect(s) - chain with OAuth/token flows for impact", use_color))
        sys.exit(1)
    print(color("92", "[✓] No open redirect detected", use_color))
    sys.exit(0)

if __name__ == "__main__":
    main()
