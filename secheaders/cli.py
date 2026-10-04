"""Command line interface: secheaders example.com [more urls] [--json] [--fail-under B]"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import GRADE_ORDER
from .report import to_json, to_text, use_color
from .scanner import ScanError, scan

EXIT_OK, EXIT_BELOW_THRESHOLD, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secheaders",
        description="Check a website's HTTP security headers and get a grade with fixes.",
        epilog="Only scan sites you own or are allowed to test.",
    )
    p.add_argument("urls", nargs="+", help="one or more URLs or domains (https:// is assumed)")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    p.add_argument("--fail-under", metavar="GRADE", choices=GRADE_ORDER,
                   help="exit with code 1 if any grade is worse than this (useful in CI)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds per request (default: 10)")
    p.add_argument("--no-redirect-check", action="store_true", help="skip the http:// → https:// check")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Windows may default to a legacy code page when output is piped; ✔ / → would then crash.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    color = use_color() and not args.no_color
    results, failed = [], False

    for url in args.urls:
        try:
            results.append(scan(url, timeout=args.timeout, check_redirect=not args.no_redirect_check))
        except ScanError as e:
            failed = True
            print(f"secheaders: {url}: {e}", file=sys.stderr)

    if args.json:
        print(to_json(results))
    elif results:
        print("\n\n".join(to_text(r, color) for r in results))

    if failed:
        return EXIT_ERROR
    if args.fail_under:
        limit = GRADE_ORDER.index(args.fail_under)
        if any(GRADE_ORDER.index(r.grade) > limit for r in results):
            return EXIT_BELOW_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
