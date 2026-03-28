"""Tests for redchain/config.py and cli.py argument handling."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestSettings(unittest.TestCase):
    """Test Pydantic Settings loading."""
    
    def test_settings_loads(self):
        from config import Settings
        s = Settings()
        self.assertIsNotNone(s)
    
    def test_default_llm_provider(self):
        from config import Settings
        s = Settings()
        self.assertEqual(s.llm_provider, "gemini")
    
    def test_default_ollama_url(self):
        from config import Settings
        s = Settings()
        self.assertEqual(s.ollama_base_url, "http://localhost:11434")
    
    def test_run_config_defaults(self):
        from config import RunConfig
        rc = RunConfig()
        self.assertEqual(rc.output_format, "both")
        self.assertEqual(rc.language, "en")
        self.assertEqual(rc.threads, 10)
        self.assertEqual(rc.profile, "full")
        self.assertIsNone(rc.proxy)


class TestClassifyTarget(unittest.TestCase):
    """Test target classification."""
    
    def test_domain(self):
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from cli import classify_target
        self.assertEqual(classify_target("example.com"), "domain")
    
    def test_ip(self):
        from cli import classify_target
        self.assertEqual(classify_target("192.168.1.1"), "ip")
    
    def test_cidr(self):
        from cli import classify_target
        self.assertEqual(classify_target("10.0.0.0/24"), "cidr")
    
    def test_url_to_domain(self):
        from cli import classify_target
        self.assertEqual(classify_target("https://example.com/path"), "domain")
    
    def test_ipv6(self):
        from cli import classify_target
        self.assertEqual(classify_target("::1"), "ip")


class TestI18n(unittest.TestCase):
    """Test internationalization module."""
    
    def test_get_message_en(self):
        from i18n import get_message
        msg = get_message("scan_start", "en")
        self.assertEqual(msg, "Starting RedChain against")
    
    def test_get_message_es(self):
        from i18n import get_message
        msg = get_message("scan_start", "es")
        self.assertEqual(msg, "Iniciando RedChain contra")
    
    def test_fallback_to_english(self):
        from i18n import get_message
        msg = get_message("scan_start", "xx_nonexistent")
        self.assertEqual(msg, "Starting RedChain against")
    
    def test_report_language_instruction(self):
        from i18n import get_report_language_instruction
        inst = get_report_language_instruction("fr")
        self.assertIn("français", inst)


class TestLLMAdapter(unittest.TestCase):
    """Test LLM adapter factory."""
    
    def test_get_gemini_adapter(self):
        from llm import get_adapter
        adapter = get_adapter("gemini", api_key="test")
        self.assertEqual(adapter.get_name(), "gemini")
    
    def test_get_openai_adapter(self):
        from llm import get_adapter
        adapter = get_adapter("openai", api_key="test")
        self.assertEqual(adapter.get_name(), "openai")
    
    def test_get_ollama_adapter(self):
        from llm import get_adapter
        adapter = get_adapter("ollama")
        self.assertEqual(adapter.get_name(), "ollama")
    
    def test_invalid_provider(self):
        from llm import get_adapter
        with self.assertRaises(ValueError):
            get_adapter("invalid_provider")
    
    def test_gemini_not_available_without_key(self):
        from llm import get_adapter
        adapter = get_adapter("gemini", api_key=None)
        self.assertFalse(adapter.is_available())


class TestReportAgent(unittest.TestCase):
    """Test report agent utilities."""
    
    def test_classify_severity(self):
        from agents.report_agent import classify_severity
        self.assertEqual(classify_severity(9.5), "Critical")
        self.assertEqual(classify_severity(7.5), "High")
        self.assertEqual(classify_severity(5.0), "Medium")
        self.assertEqual(classify_severity(2.0), "Low")
        self.assertEqual(classify_severity(0.0), "Info")
    
    def test_enrich_cve_findings(self):
        from agents.report_agent import enrich_cve_findings
        findings = [{"cvss_score": 9.8, "description": "SQL injection vulnerability"}]
        enriched = enrich_cve_findings(findings)
        self.assertEqual(enriched[0]["severity"], "Critical")
        self.assertTrue(len(enriched[0]["owasp_mapping"]) > 0)


if __name__ == "__main__":
    unittest.main()
