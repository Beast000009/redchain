"""
RedChain — Agent Unit Tests
Tests all agents in isolation with mocked external calls.
Covers: takeover, credential, nuclei, CVE normalization, OSINT, report MITRE mapping.
"""

import os
import sys
import asyncio
import unittest
from unittest.mock import patch, AsyncMock, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# ── Report Agent Tests ─────────────────────────────────────────────────────────

class TestReportAgentMITREMapping(unittest.TestCase):
    """Dynamic MITRE ATT&CK mapping in enrich_cve_findings."""

    def setUp(self):
        from agents.report_agent import enrich_cve_findings
        self.enrich = enrich_cve_findings

    def _enrich_one(self, description, cvss=5.0):
        findings = [{"cvss_score": cvss, "description": description}]
        return self.enrich(findings)[0]

    def _has_tactic(self, result: dict, ta_id: str) -> bool:
        """Check if any MITRE mapping entry starts with the given TA ID."""
        return any(m.startswith(ta_id) for m in result["mitre_mapping"])

    def test_rce_maps_to_execution(self):
        r = self._enrich_one("Remote code execution allows attacker to execute arbitrary commands", 9.8)
        self.assertTrue(self._has_tactic(r, "TA0002"), f"Expected TA0002 in {r['mitre_mapping']}")

    def test_privesc_maps_to_privesc(self):
        r = self._enrich_one("Local privilege escalation via sudo misconfiguration", 7.8)
        self.assertTrue(self._has_tactic(r, "TA0004"), f"Expected TA0004 in {r['mitre_mapping']}")

    def test_password_maps_to_credential_access(self):
        r = self._enrich_one("Default password accepted on admin panel", 9.1)
        self.assertTrue(self._has_tactic(r, "TA0006"), f"Expected TA0006 in {r['mitre_mapping']}")

    def test_hash_maps_to_credential_access(self):
        r = self._enrich_one("NTLM hash capture via pass-the-hash attack", 8.1)
        self.assertTrue(self._has_tactic(r, "TA0006"), f"Expected TA0006 in {r['mitre_mapping']}")

    def test_dos_maps_to_impact(self):
        r = self._enrich_one("Denial of service via resource exhaustion", 7.5)
        self.assertTrue(self._has_tactic(r, "TA0040"), f"Expected TA0040 in {r['mitre_mapping']}")

    def test_persistence_maps_correctly(self):
        r = self._enrich_one("Backdoor installed via cron job for persistence", 8.0)
        self.assertTrue(self._has_tactic(r, "TA0003"), f"Expected TA0003 in {r['mitre_mapping']}")

    def test_exfil_maps_correctly(self):
        r = self._enrich_one("Data exfiltration through HTTP upload channel", 8.5)
        self.assertTrue(self._has_tactic(r, "TA0010"), f"Expected TA0010 in {r['mitre_mapping']}")

    def test_unknown_falls_back_to_initial_access(self):
        r = self._enrich_one("A generic vulnerability with no specifics", 4.0)
        self.assertTrue(self._has_tactic(r, "TA0001"), f"Expected TA0001 in {r['mitre_mapping']}")

    def test_multiple_tactics_possible(self):
        r = self._enrich_one("Execute arbitrary commands and dump password hashes", 9.9)
        self.assertTrue(len(r["mitre_mapping"]) >= 2)

    def test_severity_critical(self):
        r = self._enrich_one("RCE vulnerability", 9.8)
        self.assertEqual(r["severity"], "Critical")

    def test_severity_high(self):
        r = self._enrich_one("High severity vuln", 7.5)
        self.assertEqual(r["severity"], "High")

    def test_severity_medium(self):
        r = self._enrich_one("Medium", 5.0)
        self.assertEqual(r["severity"], "Medium")

    def test_severity_low(self):
        r = self._enrich_one("Low", 2.0)
        self.assertEqual(r["severity"], "Low")

    def test_severity_info(self):
        r = self._enrich_one("Info", 0.0)
        self.assertEqual(r["severity"], "Info")

    def test_owasp_sql_injection(self):
        r = self._enrich_one("SQL injection allows database manipulation")
        self.assertTrue(any("A03" in m for m in r["owasp_mapping"]))

    def test_owasp_fallback(self):
        r = self._enrich_one("Some obscure bug that matches nothing")
        self.assertTrue(len(r["owasp_mapping"]) > 0)


# ── CVE Agent Tests ────────────────────────────────────────────────────────────

class TestCVEAgentVersionNormalization(unittest.TestCase):
    """Version string normalization in cve_agent."""

    def setUp(self):
        from agents.cve_agent import normalize_version
        self.norm = normalize_version

    def test_simple_version_unchanged(self):
        self.assertEqual(self.norm("7.4"), "7.4")

    def test_strips_p_suffix(self):
        self.assertEqual(self.norm("7.4p1"), "7.4")

    def test_strips_distro_suffix(self):
        # e.g. "1.2.3-4ubuntu5" → "1.2.3"
        result = self.norm("1.2.3-4ubuntu5")
        self.assertNotIn("ubuntu", result)

    def test_strips_debian_suffix(self):
        result = self.norm("2.8.4-1+deb10u1")
        self.assertNotIn("deb", result)

    def test_handles_none(self):
        result = self.norm(None)
        self.assertEqual(result, "")

    def test_handles_empty_string(self):
        result = self.norm("")
        self.assertEqual(result, "")

    def test_three_part_version(self):
        result = self.norm("3.14.159")
        self.assertEqual(result, "3.14.159")

    def test_strips_build_metadata(self):
        result = self.norm("1.0.0+build.123")
        self.assertNotIn("build", result)


# ── Takeover Agent Tests ───────────────────────────────────────────────────────

class TestTakeoverFingerprints(unittest.TestCase):
    """Subdomain takeover fingerprint database integrity."""

    def setUp(self):
        from agents.takeover_agent import TAKEOVER_FINGERPRINTS
        self.fps = TAKEOVER_FINGERPRINTS

    def test_has_at_least_15_services(self):
        self.assertGreaterEqual(len(self.fps), 15)

    def test_all_have_required_keys(self):
        required = {"service", "cname", "fingerprint"}
        for fp in self.fps:
            missing = required - set(fp.keys())
            self.assertEqual(missing, set(), f"Fingerprint missing keys: {fp}")

    def test_github_pages_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("GitHub Pages", services)

    def test_aws_s3_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("AWS S3", services)

    def test_azure_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("Azure", services)

    def test_netlify_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("Netlify", services)

    def test_vercel_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("Vercel", services)

    def test_heroku_present(self):
        services = [fp["service"] for fp in self.fps]
        self.assertIn("Heroku", services)

    def test_cname_is_list(self):
        for fp in self.fps:
            self.assertIsInstance(fp["cname"], list,
                f"{fp['service']} cname should be a list")
            self.assertGreater(len(fp["cname"]), 0)

    def test_fingerprint_is_non_empty_string(self):
        for fp in self.fps:
            self.assertIsInstance(fp["fingerprint"], str)
            self.assertGreater(len(fp["fingerprint"]), 5,
                f"{fp['service']} fingerprint too short")


class TestTakeoverStateHandling(unittest.TestCase):
    """run_takeover_check handles state with no alive subdomains gracefully."""

    def test_empty_state_returns_empty_findings(self):
        from agents.takeover_agent import run_takeover_check
        state = {"subdomains": [], "target": ""}
        result = asyncio.run(run_takeover_check(state))
        self.assertEqual(result.get("takeover_findings"), [])

    def test_no_alive_subs_returns_empty(self):
        from agents.takeover_agent import run_takeover_check
        state = {
            "subdomains": [{"subdomain": "dead.example.com", "alive": False}],
            "target": ""
        }
        result = asyncio.run(run_takeover_check(state))
        self.assertEqual(result.get("takeover_findings"), [])


# ── Credential Agent Tests ─────────────────────────────────────────────────────

class TestCredentialDefaults(unittest.TestCase):
    """Credential database integrity."""

    def setUp(self):
        from agents.credential_agent import DEFAULT_CREDS
        self.creds = DEFAULT_CREDS

    def test_at_least_20_creds(self):
        self.assertGreaterEqual(len(self.creds), 20)

    def test_all_are_tuples(self):
        for c in self.creds:
            self.assertIsInstance(c, tuple)
            self.assertEqual(len(c), 2)

    def test_admin_admin_present(self):
        self.assertIn(("admin", "admin"), self.creds)

    def test_root_root_present(self):
        self.assertIn(("root", "root"), self.creds)

    def test_pi_raspberry_present(self):
        self.assertIn(("pi", "raspberry"), self.creds)

    def test_all_strings(self):
        for user, pwd in self.creds:
            self.assertIsInstance(user, str)
            self.assertIsInstance(pwd, str)


class TestCredentialStateHandling(unittest.TestCase):
    """run_credential_check handles empty state gracefully."""

    def test_empty_state_returns_empty_findings(self):
        from agents.credential_agent import run_credential_check
        state = {"scan_results": [], "webapp_results": []}
        result = asyncio.run(run_credential_check(state))
        self.assertEqual(result.get("credential_findings"), [])


# ── Nuclei Agent Tests ─────────────────────────────────────────────────────────

class TestNucleiTemplateSelection(unittest.TestCase):
    """Tech-stack-aware nuclei template selection."""

    def setUp(self):
        from agents.nuclei_agent import _get_templates_for_tech, _DEFAULT_TEMPLATES
        self.get_templates = _get_templates_for_tech
        self.default_templates = _DEFAULT_TEMPLATES

    def test_empty_stack_returns_defaults(self):
        templates = self.get_templates([])
        for t in self.default_templates:
            self.assertIn(t, templates)

    def test_wordpress_adds_wordpress_templates(self):
        templates = self.get_templates(["WordPress 6.1"])
        self.assertTrue(any("wordpress" in t for t in templates))

    def test_jenkins_adds_default_logins(self):
        templates = self.get_templates(["Jenkins 2.387"])
        self.assertTrue(any("jenkins" in t for t in templates))

    def test_apache_adds_apache_templates(self):
        templates = self.get_templates(["Apache httpd 2.4.51"])
        self.assertTrue(any("apache" in t or "cves" in t for t in templates))

    def test_returns_list(self):
        templates = self.get_templates(["nginx"])
        self.assertIsInstance(templates, list)
        self.assertGreater(len(templates), 0)

    def test_multiple_tech_merged(self):
        templates = self.get_templates(["WordPress", "nginx"])
        # Should have both default + wordpress + nginx templates
        self.assertGreater(len(templates), len(self.default_templates))

    def test_no_duplicates(self):
        templates = self.get_templates(["WordPress", "WordPress"])
        self.assertEqual(len(templates), len(set(templates)))


class TestNucleiStateHandling(unittest.TestCase):
    """run_nuclei_scan fails gracefully when nuclei not installed."""

    def test_missing_nuclei_returns_empty(self):
        from agents.nuclei_agent import run_nuclei_scan
        with patch('agents.nuclei_agent.find_tool', return_value=None):
            state = {
                "target": "example.com",
                "webapp_results": [],
            }
            result = asyncio.run(run_nuclei_scan(state))
            self.assertEqual(result.get("nuclei_findings"), [])


# ── Scope Validation Tests ─────────────────────────────────────────────────────

class TestScopeValidation(unittest.TestCase):
    """validate_scope with wildcard, CIDR, and exclusion support."""

    def setUp(self):
        import json
        import tempfile
        self.scope_data = {
            "allowed": [
                "example.com",
                "*.staging.example.com",
                "10.0.0.0/24",
                "192.168.50.5"
            ],
            "excluded": [
                "prod.example.com",
                "noscan.staging.example.com"
            ]
        }
        self.scope_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump(self.scope_data, self.scope_file)
        self.scope_file.close()
        self.scope_path = self.scope_file.name

        from cli import validate_scope
        self.validate = validate_scope

    def tearDown(self):
        os.unlink(self.scope_path)

    def test_exact_match_allowed(self):
        self.assertTrue(self.validate("example.com", self.scope_path))

    def test_exact_ip_allowed(self):
        self.assertTrue(self.validate("192.168.50.5", self.scope_path))

    def test_cidr_ip_allowed(self):
        self.assertTrue(self.validate("10.0.0.55", self.scope_path))

    def test_cidr_ip_out_of_range_denied(self):
        self.assertFalse(self.validate("10.0.1.1", self.scope_path))

    def test_wildcard_subdomain_allowed(self):
        self.assertTrue(self.validate("api.staging.example.com", self.scope_path))

    def test_wildcard_another_subdomain_allowed(self):
        self.assertTrue(self.validate("test.staging.example.com", self.scope_path))

    def test_excluded_target_denied(self):
        self.assertFalse(self.validate("prod.example.com", self.scope_path))

    def test_excluded_subdomain_via_wildcard_denied(self):
        self.assertFalse(self.validate("noscan.staging.example.com", self.scope_path))

    def test_not_in_scope_denied(self):
        self.assertFalse(self.validate("notallowed.com", self.scope_path))

    def test_missing_scope_file_returns_false(self):
        self.assertFalse(self.validate("example.com", "/tmp/redchain_no_such_scope.json"))


# ── Target Classification Tests ────────────────────────────────────────────────

class TestTargetClassification(unittest.TestCase):

    def setUp(self):
        from cli import classify_target
        self.classify = classify_target

    def test_domain(self):
        self.assertEqual(self.classify("example.com"), "domain")

    def test_subdomain(self):
        self.assertEqual(self.classify("api.example.com"), "domain")

    def test_ipv4(self):
        self.assertEqual(self.classify("192.168.1.1"), "ip")

    def test_ipv6(self):
        self.assertEqual(self.classify("::1"), "ip")

    def test_cidr(self):
        self.assertEqual(self.classify("10.0.0.0/24"), "cidr")

    def test_url_https_strip(self):
        self.assertEqual(self.classify("https://example.com/path?q=1"), "domain")

    def test_url_http_strip(self):
        self.assertEqual(self.classify("http://test.org"), "domain")

    def test_url_with_port(self):
        self.assertEqual(self.classify("https://example.com:8443/admin"), "domain")


# ── OSINT Helpers Tests ────────────────────────────────────────────────────────

class TestOSINTHelpers(unittest.TestCase):
    """Test OSINT state structure — mocked to avoid real network calls."""

    def test_run_osint_returns_dict_on_network_error(self):
        """run_osint should return a dict even if all network calls fail."""
        from agents.osint_agent import run_osint
        with patch('httpx.AsyncClient.get', new_callable=AsyncMock,
                   side_effect=Exception("connection refused")):
            result = asyncio.run(run_osint("nonexistent-domain-xyz123.com"))
            self.assertIsInstance(result, dict)

    def test_passive_dns_private_function_exists(self):
        """The private passive DNS helper should exist in the module."""
        import agents.osint_agent as osint
        self.assertTrue(hasattr(osint, '_run_passive_dns'),
                        "_run_passive_dns helper should be defined")

    def test_crtsh_private_function_exists(self):
        import agents.osint_agent as osint
        self.assertTrue(hasattr(osint, '_run_crtsh'))


# ── Report Generator Tests ─────────────────────────────────────────────────────

class TestReportGeneratorNewSections(unittest.TestCase):
    """generator.py correctly includes takeover/nuclei/credential sections."""

    def test_markdown_includes_nuclei(self):
        from report.generator import generate_md
        state = {
            "target": "example.com",
            "osint_results": {},
            "subdomains": [],
            "webapp_results": [],
            "scan_results": [],
            "cve_findings": [],
            "nuclei_findings": [
                {
                    "url": "https://example.com/admin",
                    "template_name": "wordpress-login",
                    "severity": "high",
                    "cve_ids": ["CVE-2023-1234"],
                }
            ],
            "takeover_findings": [],
            "credential_findings": [],
            "node_errors": {},
            "ai_report": {},
        }
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            md = generate_md(state, path)
            if md is None:  # some implementations write and return None
                with open(path) as f:
                    md = f.read()
            self.assertIn("Nuclei Templated Scan Findings", md)
            self.assertIn("wordpress-login", md)
            self.assertIn("CVE-2023-1234", md)
        finally:
            os.unlink(path)

    def test_markdown_includes_takeover(self):
        from report.generator import generate_md
        state = {
            "target": "example.com",
            "osint_results": {},
            "subdomains": [],
            "webapp_results": [],
            "scan_results": [],
            "cve_findings": [],
            "nuclei_findings": [],
            "takeover_findings": [
                {
                    "subdomain": "old.example.com",
                    "service": "GitHub Pages",
                    "cname": "example.github.io",
                    "fingerprint_matched": "There isn't a GitHub Pages site here",
                    "url": "https://old.example.com",
                    "description": "Dangling CNAME takeover possible",
                }
            ],
            "credential_findings": [],
            "node_errors": {},
            "ai_report": {},
        }
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            md = generate_md(state, path)
            if md is None:
                with open(path) as f:
                    md = f.read()
            self.assertIn("Subdomain Takeover", md)
            self.assertIn("old.example.com", md)
            self.assertIn("GitHub Pages", md)
        finally:
            os.unlink(path)

    def test_markdown_includes_credentials(self):
        from report.generator import generate_md
        state = {
            "target": "example.com",
            "osint_results": {},
            "subdomains": [],
            "webapp_results": [],
            "scan_results": [],
            "cve_findings": [],
            "nuclei_findings": [],
            "takeover_findings": [],
            "credential_findings": [
                {
                    "host": "192.168.1.10",
                    "port": 22,
                    "service": "SSH",
                    "username": "admin",
                    "password": "admin",
                    "description": "Default SSH creds",
                }
            ],
            "node_errors": {},
            "ai_report": {},
        }
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = f.name
        try:
            md = generate_md(state, path)
            if md is None:
                with open(path) as f:
                    md = f.read()
            self.assertIn("Default Credentials", md)
            self.assertIn("admin", md)
            self.assertIn("SSH", md)
        finally:
            os.unlink(path)

    def test_json_report_includes_new_keys(self):
        from report.generator import generate_json_report
        import json, tempfile
        state = {
            "target": "example.com",
            "nuclei_findings": [{"url": "x", "severity": "high"}],
            "takeover_findings": [{"subdomain": "old.example.com"}],
            "credential_findings": [{"host": "1.2.3.4", "username": "admin"}],
            "cve_findings": [],
            "scan_results": [],
            "webapp_results": [],
            "osint_results": {},
            "node_errors": {},
            "ai_report": {},
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            generate_json_report(state, path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("nuclei_findings", data)
            self.assertIn("takeover_findings", data)
            self.assertIn("credential_findings", data)
            self.assertEqual(len(data["nuclei_findings"]), 1)
            self.assertEqual(len(data["takeover_findings"]), 1)
            self.assertEqual(len(data["credential_findings"]), 1)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
