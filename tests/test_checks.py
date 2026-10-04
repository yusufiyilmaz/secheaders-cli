import unittest

from secheaders.checks import analyze, check_blocked, detect_protection, parse_csp, score

GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def by_check(findings, name):
    return [f for f in findings if f.check == name]


def statuses(findings, name):
    return {f.status for f in by_check(findings, name)}


class TestCspParser(unittest.TestCase):
    def test_parses_directives_and_lowercases(self):
        d = parse_csp("Default-Src 'self';  script-src 'self' https://cdn.example.com ;")
        self.assertEqual(d["default-src"], ["'self'"])
        self.assertEqual(d["script-src"], ["'self'", "https://cdn.example.com"])

    def test_first_directive_wins(self):
        self.assertEqual(parse_csp("script-src 'self'; script-src *")["script-src"], ["'self'"])


class TestGrades(unittest.TestCase):
    def test_hardened_site_gets_a_plus(self):
        points, grade = score(analyze(GOOD))
        self.assertEqual((points, grade), (100, "A+"))

    def test_no_headers_gets_f(self):
        self.assertEqual(score(analyze({}))[1], "F")

    def test_one_high_severity_problem_drops_below_a(self):
        headers = dict(GOOD)
        del headers["Strict-Transport-Security"]
        self.assertEqual(score(analyze(headers)), (80, "B"))

    def test_header_names_are_case_insensitive(self):
        lower = {k.lower(): v for k, v in GOOD.items()}
        self.assertEqual(score(analyze(lower)), score(analyze(GOOD)))


class TestCsp(unittest.TestCase):
    def csp(self, value):
        return by_check(analyze({**GOOD, "Content-Security-Policy": value}), "Content-Security-Policy")

    def test_missing_csp_fails(self):
        h = dict(GOOD)
        del h["Content-Security-Policy"]
        self.assertEqual(statuses(analyze(h), "Content-Security-Policy"), {"fail"})

    def test_report_only_is_not_enough(self):
        h = dict(GOOD)
        h["Content-Security-Policy-Report-Only"] = h.pop("Content-Security-Policy")
        msg = by_check(analyze(h), "Content-Security-Policy")[0].message
        self.assertIn("Report-Only", msg)

    def test_unsafe_inline_warns(self):
        f = self.csp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
        self.assertTrue(any("unsafe-inline" in x.message for x in f))

    def test_unsafe_inline_with_nonce_is_ok(self):
        f = self.csp("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
        self.assertFalse(any("unsafe-inline" in x.message for x in f))

    def test_wildcard_script_source_warns(self):
        f = self.csp("default-src *; object-src 'none'; base-uri 'none'")
        self.assertTrue(any("broad" in x.message for x in f))

    def test_missing_object_src_and_base_uri(self):
        msgs = " ".join(x.message for x in self.csp("default-src 'self'"))
        self.assertIn("object-src", msgs)
        self.assertIn("base-uri", msgs)


class TestOtherHeaders(unittest.TestCase):
    def test_short_hsts_warns(self):
        f = analyze({**GOOD, "Strict-Transport-Security": "max-age=300"})
        self.assertEqual(statuses(f, "Strict-Transport-Security"), {"warn"})

    def test_hsts_without_subdomains_warns_low(self):
        f = by_check(analyze({**GOOD, "Strict-Transport-Security": "max-age=31536000"}), "Strict-Transport-Security")
        self.assertEqual((f[0].status, f[0].severity), ("warn", "low"))

    def test_x_frame_options_counts_without_frame_ancestors(self):
        csp = "default-src 'self'; object-src 'none'; base-uri 'none'"
        f = analyze({**GOOD, "Content-Security-Policy": csp, "X-Frame-Options": "DENY"})
        self.assertEqual(statuses(f, "Clickjacking protection"), {"pass"})

    def test_no_framing_protection_fails(self):
        csp = "default-src 'self'; object-src 'none'; base-uri 'none'"
        f = analyze({**GOOD, "Content-Security-Policy": csp})
        self.assertEqual(statuses(f, "Clickjacking protection"), {"fail"})

    def test_leaky_referrer_policy_warns(self):
        f = analyze({**GOOD, "Referrer-Policy": "unsafe-url"})
        self.assertEqual(statuses(f, "Referrer-Policy"), {"warn"})

    def test_version_disclosure(self):
        f = by_check(analyze({**GOOD, "Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4"}), "Information disclosure")
        self.assertEqual(len(f), 2)

    def test_server_name_without_version_is_fine(self):
        f = analyze({**GOOD, "Server": "cloudflare"})
        self.assertEqual(statuses(f, "Information disclosure"), {"pass"})


class TestCookies(unittest.TestCase):
    def test_insecure_cookie_flags(self):
        f = by_check(analyze(GOOD, ["session=abc; Path=/"]), "Cookies")
        msgs = " ".join(x.message for x in f)
        for flag in ("Secure", "HttpOnly", "SameSite"):
            self.assertIn(flag, msgs)

    def test_secure_cookie_passes(self):
        f = analyze(GOOD, ["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])
        self.assertEqual(statuses(f, "Cookies"), {"pass"})

    def test_cookie_value_with_equals_sign(self):
        f = analyze(GOOD, ["token=a=b==; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(statuses(f, "Cookies"), {"pass"})


class TestBlocked(unittest.TestCase):
    def test_normal_response_is_not_blocked(self):
        self.assertEqual(check_blocked(200, {"server": "cloudflare"}, []), [])

    def test_cloudflare_challenge_is_detected(self):
        f = check_blocked(403, {"server": "cloudflare", "cf-mitigated": "challenge"}, [])
        self.assertEqual(len(f), 1)
        self.assertIn("Cloudflare", f[0].message)
        self.assertEqual(f[0].penalty, 0)  # a warning, but it must not change the score

    def test_unknown_vendor_still_warns(self):
        f = check_blocked(429, {}, [])
        self.assertIn("HTTP 429", f[0].message)

    def test_vendor_fingerprints(self):
        self.assertEqual(detect_protection({"x-iinfo": "1"}, []), "Imperva")
        self.assertEqual(detect_protection({}, ["visid_incap_1=x"]), "Imperva")
        self.assertEqual(detect_protection({"server": "AkamaiGHost"}, []), "Akamai")
        self.assertIsNone(detect_protection({"server": "nginx"}, []))


if __name__ == "__main__":
    unittest.main()
