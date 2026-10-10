# Changelog

## Unreleased

- Ecosystem standardization: SECURITY.md, CONTRIBUTING.md, requirements, CI smoke checks.

## 1.0.0 (2026-09-18)

- Initial stable single-tool release (educational, authorized-use only).

## [3.0.0] - 2026-10-10
### Added
- Unified TBH v3 CLI: --proxy, --cookie, -H, --param, --timeout, --delay, --json, --version, --no-color
- Baseline request before testing (false-positive reduction)
- Multiple payloads / probes, exit codes for pipelines (0 clean, 1 finding, 2 error)
- Consistent JSON report schema (tool, version, target, baseline, findings, summary)
### Changed
- Honest versioning and User-Agent with repo link
- Proper requests.RequestException handling (no bare except)
