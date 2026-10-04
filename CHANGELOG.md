# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-05

First public release.

### Added

- Checks for HTTPS redirect, `Strict-Transport-Security`, `Content-Security-Policy`, clickjacking protection
  (`frame-ancestors` / `X-Frame-Options`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener-Policy`, version disclosure (`Server`, `X-Powered-By`) and cookie flags.
- CSP analysis: `'unsafe-inline'` (aware of nonces/hashes), `'unsafe-eval'`, wildcard script sources,
  missing `object-src` and `base-uri`, Report-Only-only policies.
- Scoring from 0 to 100 and grades from A+ to F, with a concrete fix for every finding.
- Colored terminal report and `--json` output.
- `--fail-under GRADE` exit code for CI pipelines; scanning several URLs at once.
- 28 unit and integration tests and a GitHub Actions workflow (Linux and Windows, Python 3.9 to 3.13).

[0.1.0]: https://github.com/yusufiyilmaz/secheaders-cli/releases/tag/v0.1.0
