# TBH-OpenRedirect

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-OpenRedirect/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-OpenRedirect/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/payload-safe-green.svg" alt="Safe payloads">
</p>

Open redirect detector. Swaps redirect parameters with an external marker host and checks whether the server's `Location` header follows.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## What It Checks

- Redirect/next/return-style parameters that control a `Location` or meta-refresh
- Reflection of an attacker-chosen host in the redirect target
- Bypass filters (protocol-relative, `//`, encoded variants) as a signal

Redirects are Low/Medium severity alone but become High when chained with OAuth flows or token leakage — mention the chain in your report.

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-OpenRedirect
cd TBH-OpenRedirect
pip install -r requirements.txt
```

## Usage

```
usage: redirect.py [-h] -u URL [--json JSON]

options:
  -u, --url URL     Target URL with a redirect parameter
  --json JSON       Save result as JSON
```

```bash
python3 redirect.py -u "https://example.com/login?next=/home" --json result.json
```

## Sample Output

```
[*] Testing https://example.com/login?next=/home
[!] OpenRedirect: Location header points to external host -> report with chain context
[✓] JSON: result.json
```

## Authorized Use Only

Only against scopes you own or are authorized to test. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-SSRF](https://github.com/TulungagungBlackHat/TBH-SSRF) — server-side fetch sibling
- [TBH-AllScan](https://github.com/TulungagungBlackHat/TBH-AllScan) — redirect module inside the 10-in-one scan

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
