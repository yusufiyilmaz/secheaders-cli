"""Security header checks.

Every check is a pure function: it takes response headers and returns findings.
No network access happens here, which keeps the logic easy to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Points subtracted from 100 for each failed / warned finding.
SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 4, "info": 0}

# HSTS max-age below ~6 months is considered too short.
HSTS_MIN_AGE = 15_552_000


@dataclass
class Finding:
    check: str          # header or topic, e.g. "Strict-Transport-Security"
    status: str         # "pass" | "warn" | "fail" | "info"
    severity: str       # "high" | "medium" | "low" | "info"
    message: str
    fix: str = ""

    @property
    def penalty(self) -> int:
        return SEVERITY_POINTS[self.severity] if self.status in ("warn", "fail") else 0


def _ok(check: str, message: str) -> Finding:
    return Finding(check, "pass", "info", message)


# --------------------------------------------------------------------------- CSP

def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into {directive: [sources]}. The first occurrence of a directive wins, like browsers do."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = [t.lower() for t in tokens[1:]]
    return directives


def check_csp(h: dict[str, str]) -> list[Finding]:
    name = "Content-Security-Policy"
    value = h.get("content-security-policy")
    if not value:
        if h.get("content-security-policy-report-only"):
            return [Finding(name, "fail", "high", "Only a Report-Only policy is set; nothing is actually enforced.",
                            "Move the tested policy to the Content-Security-Policy header.")]
        return [Finding(name, "fail", "high", "Header is missing. Any XSS bug can run attacker scripts.",
                        "Start with: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")]

    d = parse_csp(value)
    out: list[Finding] = []
    scripts = d.get("script-src", d.get("default-src"))

    if scripts is None:
        out.append(Finding(name, "warn", "high", "No script-src or default-src: scripts are not restricted at all.",
                           "Add default-src 'self' (or a strict script-src)."))
    else:
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts)
        if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
            out.append(Finding(name, "warn", "high", "Scripts allow 'unsafe-inline', which defeats most XSS protection.",
                               "Move inline scripts to files, or use nonces/hashes instead of 'unsafe-inline'."))
        if "'unsafe-eval'" in scripts:
            out.append(Finding(name, "warn", "medium", "Scripts allow 'unsafe-eval' (eval, new Function).",
                               "Remove 'unsafe-eval' and avoid eval-style code."))
        wide = [s for s in scripts if s in ("*", "http:", "https:", "data:")]
        if wide:
            out.append(Finding(name, "warn", "high", f"Scripts may load from very broad sources: {' '.join(wide)}",
                               "List only the exact origins you need, e.g. 'self' https://cdn.example.com"))

    default_none = d.get("default-src") == ["'none'"]
    if "object-src" not in d and not default_none:
        out.append(Finding(name, "warn", "low", "object-src is not set (plugins like <object>/<embed> are allowed).",
                           "Add object-src 'none'."))
    if "base-uri" not in d:
        out.append(Finding(name, "warn", "low", "base-uri is not set; an injected <base> tag could redirect relative URLs.",
                           "Add base-uri 'none' (or 'self')."))

    if not out:
        out.append(_ok(name, "Policy is present and has no obvious weaknesses."))
    return out


# --------------------------------------------------------------------- other headers

def check_hsts(h: dict[str, str], is_https: bool) -> list[Finding]:
    name = "Strict-Transport-Security"
    if not is_https:
        return [Finding(name, "fail", "high", "The site is not served over HTTPS, so HSTS cannot apply.",
                        "Serve the site over HTTPS, then add HSTS.")]
    value = h.get("strict-transport-security")
    if not value:
        return [Finding(name, "fail", "high", "Header is missing. Users can be downgraded to plain HTTP.",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    if age < HSTS_MIN_AGE:
        return [Finding(name, "warn", "medium", f"max-age is only {age} seconds (less than 6 months).",
                        "Use max-age=31536000 (1 year) or more.")]
    if "includesubdomains" not in value.lower():
        return [Finding(name, "warn", "low", "includeSubDomains is missing; subdomains are not protected.",
                        "Add includeSubDomains if all subdomains support HTTPS.")]
    return [_ok(name, f"Enabled for {age // 86400} days, including subdomains.")]


def check_content_type_options(h: dict[str, str]) -> list[Finding]:
    name = "X-Content-Type-Options"
    if h.get("x-content-type-options", "").strip().lower() == "nosniff":
        return [_ok(name, "nosniff is set.")]
    return [Finding(name, "fail", "medium", "Missing or not 'nosniff'; browsers may guess (sniff) file types.",
                    "X-Content-Type-Options: nosniff")]


def check_framing(h: dict[str, str]) -> list[Finding]:
    name = "Clickjacking protection"
    csp = parse_csp(h.get("content-security-policy", ""))
    if "frame-ancestors" in csp:
        return [_ok(name, "CSP frame-ancestors is set: " + " ".join(csp["frame-ancestors"]))]
    xfo = h.get("x-frame-options", "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return [_ok(name, f"X-Frame-Options: {xfo}")]
    if xfo.startswith("ALLOW-FROM"):
        return [Finding(name, "warn", "medium", "ALLOW-FROM is obsolete and ignored by modern browsers.",
                        "Use CSP frame-ancestors instead.")]
    return [Finding(name, "fail", "medium", "The page can be embedded in an iframe on any site (clickjacking).",
                    "Add CSP frame-ancestors 'none' (or X-Frame-Options: DENY).")]


def check_referrer(h: dict[str, str]) -> list[Finding]:
    name = "Referrer-Policy"
    value = h.get("referrer-policy", "").strip().lower()
    if not value:
        return [Finding(name, "warn", "low", "Not set (browsers fall back to a reasonable default).",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    # The last valid token wins when several are listed.
    policy = value.split(",")[-1].strip()
    if policy in ("unsafe-url", "no-referrer-when-downgrade"):
        return [Finding(name, "warn", "medium", f"'{policy}' can leak full URLs to other sites.",
                        "Use strict-origin-when-cross-origin or no-referrer.")]
    return [_ok(name, policy)]


def check_permissions(h: dict[str, str]) -> list[Finding]:
    name = "Permissions-Policy"
    if h.get("permissions-policy"):
        return [_ok(name, "Browser features are restricted.")]
    return [Finding(name, "warn", "low", "Not set; embedded content may request camera, microphone, location, etc.",
                    "Permissions-Policy: camera=(), microphone=(), geolocation=()")]


def check_coop(h: dict[str, str]) -> list[Finding]:
    name = "Cross-Origin-Opener-Policy"
    value = h.get("cross-origin-opener-policy", "").strip().lower()
    if value in ("same-origin", "same-origin-allow-popups"):
        return [_ok(name, value)]
    return [Finding(name, "warn", "low", "Not set; other windows can keep a reference to this page.",
                    "Cross-Origin-Opener-Policy: same-origin")]


def check_disclosure(h: dict[str, str]) -> list[Finding]:
    name = "Information disclosure"
    out: list[Finding] = []
    server = h.get("server", "")
    if re.search(r"\d", server):
        out.append(Finding(name, "warn", "low", f"Server header reveals a version: {server}",
                           "Hide version numbers in the Server header."))
    for header in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h.get(header):
            out.append(Finding(name, "warn", "low", f"{header} reveals the technology stack: {h[header]}",
                               f"Remove the {header} header."))
    return out or [_ok(name, "No version or technology headers found.")]


def check_xss_protection(h: dict[str, str]) -> list[Finding]:
    value = h.get("x-xss-protection", "").strip()
    if value and not value.startswith("0"):
        return [Finding("X-XSS-Protection", "info", "info",
                        "This header is deprecated; the old filter could itself be abused.",
                        "Remove it (or set it to 0) and rely on CSP.")]
    return []


def check_cookies(set_cookies: list[str], is_https: bool) -> list[Finding]:
    name = "Cookies"
    if not set_cookies:
        return [Finding(name, "info", "info", "No cookies were set on this response.")]
    out: list[Finding] = []
    for raw in set_cookies:
        cookie_name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        if is_https and "secure" not in attrs:
            out.append(Finding(name, "warn", "medium", f"'{cookie_name}' has no Secure flag (can travel over HTTP).",
                               "Add the Secure attribute."))
        if "httponly" not in attrs:
            out.append(Finding(name, "warn", "low", f"'{cookie_name}' has no HttpOnly flag (readable by JavaScript).",
                               "Add HttpOnly unless JavaScript really needs this cookie."))
        if "samesite" not in attrs:
            out.append(Finding(name, "warn", "low", f"'{cookie_name}' has no SameSite attribute (CSRF risk).",
                               "Add SameSite=Lax (or Strict)."))
    return out or [_ok(name, f"{len(set_cookies)} cookie(s) with Secure, HttpOnly and SameSite.")]


# --------------------------------------------------------------------- aggregate

def analyze(headers: dict[str, str], set_cookies: list[str] | None = None, is_https: bool = True) -> list[Finding]:
    """Run every check. Header names are matched case-insensitively."""
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []
    findings += check_hsts(h, is_https)
    findings += check_csp(h)
    findings += check_framing(h)
    findings += check_content_type_options(h)
    findings += check_referrer(h)
    findings += check_permissions(h)
    findings += check_coop(h)
    findings += check_disclosure(h)
    findings += check_xss_protection(h)
    findings += check_cookies(set_cookies or [], is_https)
    return findings


GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]
GRADE_ORDER = [g for _, g in GRADES]


def score(findings: list[Finding]) -> tuple[int, str]:
    # A single high-severity problem costs 20 points, so it alone is enough to drop a site below "A".
    points = max(0, 100 - sum(f.penalty for f in findings))
    grade = next(g for limit, g in GRADES if points >= limit)
    return points, grade
