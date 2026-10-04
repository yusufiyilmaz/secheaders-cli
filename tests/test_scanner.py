"""Integration tests against a real local HTTP server (no internet needed)."""

import http.server
import io
import json
import threading
import unittest
from contextlib import redirect_stdout

from secheaders.cli import main
from secheaders.report import to_text
from secheaders.scanner import ScanError, check_https_redirect, normalize, scan


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/hardened":
            self.send_response(200)
            self.send_header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax")
        elif self.path == "/blocked":
            # mimics a Cloudflare bot challenge
            self.send_response(403)
            self.send_header("Server", "cloudflare")
            self.send_header("cf-mitigated", "challenge")
        elif self.path == "/missing":
            self.send_response(404)
            self.send_header("X-Powered-By", "Express")
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class TestScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_reads_headers_from_server(self):
        r = scan(self.base + "/hardened")
        csp = [f for f in r.findings if f.check == "Content-Security-Policy"]
        self.assertEqual({f.status for f in csp}, {"pass"})
        # served over plain HTTP, so HSTS must fail
        hsts = [f for f in r.findings if f.check == "Strict-Transport-Security"]
        self.assertEqual(hsts[0].status, "fail")

    def test_error_pages_are_still_analyzed(self):
        r = scan(self.base + "/missing")
        self.assertEqual(r.status, 404)
        self.assertTrue(any("Express" in f.message for f in r.findings))

    def test_bot_challenge_is_flagged(self):
        r = scan(self.base + "/blocked")
        self.assertTrue(r.blocked)
        self.assertEqual(r.findings[0].check, "Blocked response")
        self.assertIn("note", to_text(r))

    def test_normal_page_is_not_flagged(self):
        self.assertFalse(scan(self.base + "/hardened").blocked)

    def test_redirect_check_does_not_fail_on_blocked_http(self):
        # check_https_redirect swaps https:// for http://, which hits our local server's /blocked page
        f = check_https_redirect("https" + self.base[4:] + "/blocked", timeout=5)
        self.assertEqual(f.status, "info")
        self.assertIn("Could not verify", f.message)

    def test_connection_refused_raises_scan_error(self):
        with self.assertRaises(ScanError):
            scan("http://127.0.0.1:1/", timeout=2)

    def test_cli_json_and_fail_under(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([self.base + "/", "--json", "--fail-under", "A"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["grade"], "F")
        self.assertEqual(code, 1)


class TestNormalize(unittest.TestCase):
    def test_adds_https_and_path(self):
        self.assertEqual(normalize("example.com"), "https://example.com/")

    def test_rejects_other_schemes(self):
        with self.assertRaises(ScanError):
            normalize("ftp://example.com")


if __name__ == "__main__":
    unittest.main()
