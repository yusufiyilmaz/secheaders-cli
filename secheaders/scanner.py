"""Network side: fetch a URL and hand its headers to the checks."""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .checks import BLOCK_STATUSES, Finding, analyze, check_blocked, score

USER_AGENT = f"secheaders/{__version__} (+https://github.com/yusufiyilmaz/secheaders-cli)"


class ScanError(Exception):
    """Raised when a URL cannot be fetched at all."""


@dataclass
class Result:
    url: str
    final_url: str
    status: int
    elapsed: float
    score: int
    grade: str
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False  # True when the response looks like a block / bot-challenge page


def normalize(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScanError(f"Not a valid http(s) URL: {url}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def fetch(url: str, timeout: float = 10.0):
    """GET the URL (following redirects). Returns (final_url, status, headers, set_cookies)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        # 4xx/5xx responses still carry headers worth checking.
        resp = e
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise ScanError(f"TLS certificate error: {reason.verify_message}") from e
        if isinstance(reason, socket.gaierror):
            raise ScanError(f"Could not resolve host: {urlsplit(url).hostname}") from e
        raise ScanError(f"Connection failed: {reason}") from e
    except (TimeoutError, socket.timeout) as e:
        raise ScanError(f"Timed out after {timeout:g}s") from e

    with resp:
        resp.read(1024)  # we only need the headers
        headers = {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
        cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.geturl(), resp.status if hasattr(resp, "status") else resp.code, headers, cookies


def check_https_redirect(url: str, timeout: float) -> Finding:
    """Does plain http:// send visitors to https://?"""
    name = "HTTPS redirect"
    parts = urlsplit(url)
    http_url = urlunsplit(("http", parts.netloc, parts.path or "/", parts.query, ""))
    try:
        final, status, *_ = fetch(http_url, timeout)
    except ScanError as e:
        return Finding(name, "info", "info", f"Plain HTTP could not be checked ({e}).")
    if urlsplit(final).scheme == "https":
        return Finding(name, "pass", "info", "http:// redirects to https://")
    if status in BLOCK_STATUSES:
        # A block/challenge page answered instead of the site, so we cannot tell whether it redirects.
        return Finding(name, "info", "info", f"Could not verify: plain HTTP returned HTTP {status} (likely blocked).")
    return Finding(name, "fail", "high", "http:// does not redirect to https://; visitors can stay on plain HTTP.",
                   "Redirect all HTTP traffic to HTTPS (301).")


def scan(url: str, timeout: float = 10.0, check_redirect: bool = True) -> Result:
    url = normalize(url)
    t0 = time.perf_counter()
    final, status, headers, cookies = fetch(url, timeout)
    elapsed = time.perf_counter() - t0

    is_https = urlsplit(final).scheme == "https"
    blocked = check_blocked(status, {k.lower(): v for k, v in headers.items()}, cookies)
    findings = blocked + analyze(headers, cookies, is_https)
    if check_redirect and urlsplit(url).scheme == "https":
        findings.insert(len(blocked), check_https_redirect(url, timeout))

    points, grade = score(findings)
    return Result(url, final, status, elapsed, points, grade, findings, blocked=bool(blocked))
