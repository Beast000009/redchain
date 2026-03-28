"""Tests for redchain/models.py — Pydantic data models."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models import WhoisData, ShodanHost, AsnInfo, DorkResult, OsintResult


class TestWhoisData(unittest.TestCase):
    def test_creation(self):
        w = WhoisData(registrar="GoDaddy", creation_date="2020-01-01",
                     expiration_date="2025-01-01", name_servers=["ns1.example.com"],
                     registrant_org="Test Corp", registrant_country="US",
                     abuse_email="abuse@example.com")
        self.assertEqual(w.registrar, "GoDaddy")
        self.assertEqual(w.registrant_country, "US")
    
    def test_name_servers_list(self):
        w = WhoisData(registrar="", creation_date="", expiration_date="",
                     name_servers=["ns1.test.com", "ns2.test.com"],
                     registrant_org="", registrant_country="", abuse_email="")
        self.assertEqual(len(w.name_servers), 2)


class TestShodanHost(unittest.TestCase):
    def test_creation(self):
        s = ShodanHost(ip="1.2.3.4", ports=[80, 443], hostnames=["example.com"],
                      org="TestCorp", os="Linux", vulns=["CVE-2024-1234"],
                      banners=["Apache/2.4"], last_update="2024-01-01")
        self.assertEqual(s.ip, "1.2.3.4")
        self.assertEqual(s.ports, [80, 443])
        self.assertEqual(len(s.vulns), 1)


class TestAsnInfo(unittest.TestCase):
    def test_creation(self):
        a = AsnInfo(asn="AS1234", org="TestISP", country="US",
                   ip_ranges=["1.2.3.0/24"], abuse_email="abuse@isp.com")
        self.assertEqual(a.asn, "AS1234")


class TestDorkResult(unittest.TestCase):
    def test_creation(self):
        d = DorkResult(dork='site:example.com filetype:pdf', 
                      description="PDF files on target")
        self.assertEqual(d.dork, 'site:example.com filetype:pdf')


class TestOsintResult(unittest.TestCase):
    def test_default_lists(self):
        o = OsintResult(domain="example.com")
        self.assertEqual(o.hostnames, [])
        self.assertEqual(o.emails, [])
        self.assertEqual(o.errors, {})

    def test_serialization(self):
        o = OsintResult(domain="example.com", hostnames=["www.example.com"], 
                       emails=["admin@example.com"])
        data = o.model_dump()
        self.assertIn("hostnames", data)
        self.assertEqual(data["hostnames"], ["www.example.com"])
        self.assertEqual(data["domain"], "example.com")


if __name__ == "__main__":
    unittest.main()
