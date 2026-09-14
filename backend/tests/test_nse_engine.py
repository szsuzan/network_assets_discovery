import os
import unittest
import glob

from app.services import nse_engine
from app.services.risk_rules import RISK_RULES


def assert_evidence_ok(test, finding, expect_type=None, expect_script=None, port=None):
    """Every finding MUST carry evidence whose script id matches its claim and
    whose output is non-empty -- the core evidence/finding consistency rule."""
    test.assertEqual(finding["type"], expect_type, "finding type mismatch")
    if port is not None:
        test.assertEqual(finding["port"], port)
    ev = finding.get("evidence")
    test.assertIsInstance(ev, dict, "evidence must be a dict")
    test.assertTrue(ev.get("script"), "evidence script id missing")
    test.assertTrue((ev.get("output") or "").strip(), "evidence output is empty")
    if expect_script:
        test.assertEqual(ev["script"], expect_script)


def cert_entry(output, elems=None):
    return {"script": "ssl-cert", "output": output, "elems": elems or {}}


class TestSshRules(unittest.TestCase):
    def test_weak_kex_and_hostkey(self):
        # Real output shape from scan 9569ee00 (192.168.1.254).
        out = ("kex_algorithms: (8)\n      curve25519-sha256\n      diffie-hellman-group14-sha256\n"
               "      diffie-hellman-group14-sha1\n      kexguess2@matt.ucc.asn.au\n"
               "  server_host_key_algorithms: (2)\n      rsa-sha2-256\n      ssh-rsa")
        findings = nse_engine._rule_ssh({"script": "ssh2-enum-algos", "output": out, "elems": {}}, 22)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "weak_crypto", "ssh2-enum-algos", 22)
        self.assertIn("diffie-hellman-group14-sha1", findings[0]["description"])
        self.assertIn("ssh-rsa", findings[0]["description"])

    def test_clean_kex_no_finding(self):
        out = "kex_algorithms: (3)\n      curve25519-sha256\n      sntrup761x25519-sha512\n      diffie-hellman-group16-sha512"
        self.assertEqual(nse_engine._rule_ssh({"script": "ssh2-enum-algos", "output": out, "elems": {}}, 22), [])

    def test_short_rsa_hostkey(self):
        out = "1024-bit RSA host key"
        findings = nse_engine._rule_ssh({"script": "ssh-hostkey", "output": out, "elems": {}}, 22)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "weak_crypto", "ssh-hostkey", 22)


class TestSslCertRules(unittest.TestCase):
    def test_expired_cert_naive_text(self):
        # Real Hikvision camera output: no timezone in the dates.
        out = ("Subject: commonName=99a8a665455a3aa3bdce2bb498a7392f\n"
               "Not valid before: 1969-12-31T16:00:40\nNot valid after:  1972-12-30T16:00:40")
        elems = {"subject/commonName": "99a8a665455a3aa3bdce2bb498a7392f",
                 "issuer/commonName": "99a8a665455a3aa3bdce2bb498a7392f",
                 "pubkey/bits": "1024"}
        findings = nse_engine._rule_ssl_cert(cert_entry(out, elems), 443)
        types = {f["type"] for f in findings}
        self.assertIn("expired_certificate", types)
        self.assertIn("weak_crypto", types)
        for f in findings:
            assert_evidence_ok(self, f, f["type"], port=443)

    def test_expired_cert_xml_validity_path(self):
        findings = nse_engine._rule_ssl_cert(cert_entry("", {"validity/notAfter": "2020-01-01T00:00:00"}), 443)
        self.assertEqual([f["type"] for f in findings], ["expired_certificate"])
        assert_evidence_ok(self, findings[0], "expired_certificate", port=443)

    def test_future_cert_no_expired(self):
        # AnyDesk valid certs (2025->2075) must NOT be flagged expired.
        out = "Subject: commonName=AnyDesk Client\nNot valid before: 2025-11-23T09:30:54\nNot valid after:  2075-11-11T09:30:54"
        findings = nse_engine._rule_ssl_cert(cert_entry(out, {"pubkey/bits": "2048", "subject/commonName": "AnyDesk Client", "issuer/commonName": "AnyDesk Client"}), 7070)
        self.assertEqual([f["type"] for f in findings], ["weak_crypto"])

    def test_self_signed(self):
        findings = nse_engine._rule_ssl_cert(cert_entry(
            "Subject: commonName=host\nNot valid after:  2030-01-01T00:00:00",
            {"subject/commonName": "host", "issuer/commonName": "host"}), 443)
        self.assertEqual([f["type"] for f in findings], ["weak_crypto"])
        self.assertIn("Self-signed", findings[0]["title"])


class TestSslCiphersRules(unittest.TestCase):
    def test_weak_suites(self):
        out = "TLSv1.1:\n  TLS_RSA_WITH_RC4_128_SHA\nTLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        findings = nse_engine._rule_ssl_ciphers({"script": "ssl-enum-ciphers", "output": out, "elems": {}}, 443)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "weak_crypto", "ssl-enum-ciphers", 443)
        self.assertIn("RC4", findings[0]["description"])

    def test_deprecated_protocol(self):
        out = "SSLv3:\n  TLS_RSA_WITH_AES_128_CBC_SHA\nTLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        findings = nse_engine._rule_ssl_ciphers({"script": "ssl-enum-ciphers", "output": out, "elems": {}}, 443)
        self.assertEqual(len(findings), 1)
        self.assertIn("SSLv3", findings[0]["description"])

    def test_clean_tls12_no_finding(self):
        out = "TLSv1.2:\n  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\nTLSv1.3:"
        self.assertEqual(nse_engine._rule_ssl_ciphers({"script": "ssl-enum-ciphers", "output": out, "elems": {}}, 443), [])


class TestSmpRules(unittest.TestCase):
    def test_signing_not_required(self):
        out = "Message signing enabled but not required\n"
        findings = nse_engine._rule_smb_signing({"script": "smb-security-mode", "output": out, "elems": {}}, 445)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "smb_signing_disabled", "smb-security-mode", 445)

    def test_signing_disabled(self):
        out = "Message signing disabled\n"
        findings = nse_engine._rule_smb_signing({"script": "smb-security-mode", "output": out, "elems": {}}, 445)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "smb_signing_disabled", port=445)

    def test_signing_required_no_finding(self):
        # Real output from scan 9569ee00 (192.168.1.139).
        out = "\n  3:1:1: \n    Message signing enabled and required\n"
        self.assertEqual(nse_engine._rule_smb_signing({"script": "smb2-security-mode", "output": out, "elems": {}}, 445), [])

    def test_writable_share_structured(self):
        el = {"Everyone/anonymous access": "READ/WRITE"}
        findings = nse_engine._rule_smb_shares({"script": "smb-enum-shares", "output": "", "elems": el}, 445)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "unrestricted_share", "smb-enum-shares", 445)

    def test_smbv1_enabled(self):
        out = "  dialects: \n    1:0:0\n    2:0:2"
        findings = nse_engine._rule_smbv1({"script": "smb-protocols", "output": out, "elems": {"1:0:0": "1:0:0"}}, 445)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "smbv1_enabled", "smb-protocols", 445)

    def test_smbv1_absent_no_finding(self):
        out = "  dialects: \n    2:0:2\n    2:1:0\n    3:0:0\n    3:1:1"
        self.assertEqual(nse_engine._rule_smbv1({"script": "smb-protocols", "output": out, "elems": {}}, 445), [])


class TestAppRules(unittest.TestCase):
    def test_ftp_anon(self):
        out = "Anonymous FTP login allowed (FTP code 230)"
        findings = nse_engine._rule_ftp_anon({"script": "ftp-anon", "output": out, "elems": {}}, 21)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "anonymous_ftp", "ftp-anon", 21)

    def test_http_methods(self):
        out = "Supported Methods: GET HEAD\nPotentially risky methods: TRACE\n"
        findings = nse_engine._rule_http_methods({"script": "http-methods", "output": out, "elems": {}}, 80)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "dangerous_http_methods", "http-methods", 80)

    def test_telnet_no_encryption_real_output(self):
        # Real output from scan 9569ee00 (192.168.1.200).
        out = "\n  Telnet server does not support encryption"
        findings = nse_engine._rule_telnet({"script": "telnet-encryption", "output": out, "elems": {}}, 23)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "unencrypted_protocol", "telnet-encryption", 23)

    def test_telnet_supports_encryption_no_finding(self):
        out = "Telnet server supports encryption"
        self.assertEqual(nse_engine._rule_telnet({"script": "telnet-encryption", "output": out, "elems": {}}, 23), [])

    def test_mysql_empty_password_real_phrase(self):
        # Real nmap mysql-empty-password output phrase.
        out = "MySQL server allows empty password. Please check mysql.user table."
        findings = nse_engine._rule_mysql_empty({"script": "mysql-empty-password", "output": out, "elems": {}}, 3306)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "empty_password", "mysql-empty-password", 3306)

    def test_mysql_blocked_host_no_finding(self):
        # Real output from scan 9569ee00 (192.168.1.139): host banned, NOT empty pw.
        out = "Host '192.168.1.139' is not allowed to connect to this MySQL server"
        self.assertEqual(nse_engine._rule_mysql_empty({"script": "mysql-empty-password", "output": out, "elems": {}}, 3306), [])

    def test_mongo_auth_disabled(self):
        out = "Authentication: not enabled"
        findings = nse_engine._rule_mongo_auth({"script": "mongodb-info", "output": out, "elems": {}}, 27017)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "missing_auth", "mongodb-info", 27017)

    def test_vnc_no_auth(self):
        out = "Authentication required: No\n"
        findings = nse_engine._rule_login_less_services({"script": "vnc-info", "output": out, "elems": {}}, 5900)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "missing_auth", "vnc-info", 5900)


class TestVulnRules(unittest.TestCase):
    def test_smb_vuln(self):
        out = ("VULNERABLE\n  IDs:  CVE-2017-0143\n  Risk factor: HIGH\n  Summary: Remote code execution")
        findings = nse_engine._rule_smb_vuln({"script": "smb-vuln-ms17-010", "output": out, "elems": {}}, 445)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "known_vulnerability", "smb-vuln-ms17-010", 445)
        self.assertIn("CVE-2017-0143", findings[0]["cve_refs"])

    def test_smb_not_vulnerable_no_finding(self):
        out = "Host is probably patched. Not vulnerable."
        self.assertEqual(nse_engine._rule_smb_vuln({"script": "smb-vuln-ms17-010", "output": out, "elems": {}}, 445), [])

    def test_ssl_dos(self):
        out = "VULNERABLE\n  IDs:  CVE-2016-2183\n  Risk factor: Medium"
        findings = nse_engine._rule_ssl_dos({"script": "ssl-dh-params", "output": out, "elems": {}}, 443)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "known_vulnerability", "ssl-dh-params", 443)


class TestDnsSmtpX11RdpRules(unittest.TestCase):
    def test_dns_zone_transfer(self):
        out = "Attempting zone transfer for example.com at 192.168.1.10\nMISC\nSUCCESS"
        findings = nse_engine._rule_dns_zone_transfer({"script": "dns-zone-transfer", "output": out, "elems": {}}, 53)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "information_disclosure", "dns-zone-transfer", 53)

    def test_dns_recursion(self):
        findings = nse_engine._rule_dns_recursion({"script": "dns-recursion", "output": "recursion is enabled", "elems": {}}, 53)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "open_dns_recursion", "dns-recursion", 53)
        self.assertEqual(nse_engine._rule_dns_recursion({"script": "dns-recursion", "output": "recursion is not enabled", "elems": {}}, 53), [])

    def test_smtp_open_relay(self):
        out = "\nServer: mail.example\nPort: 25\n\n  Relay: enabled"
        findings = nse_engine._rule_smtp_relay({"script": "smtp-open-relay", "output": out, "elems": {}}, 25)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "smtp_open_relay", "smtp-open-relay", 25)
        self.assertEqual(nse_engine._rule_smtp_relay({"script": "smtp-open-relay", "output": "\n  Relay: not enabled", "elems": {}}, 25), [])

    def test_x11(self):
        findings = nse_engine._rule_x11({"script": "x11-access", "output": "X11 server access control is disabled (no .Xauthority)", "elems": {}}, 6000)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "x11_exposed", "x11-access", 6000)

    def test_rdp_nla_disabled(self):
        out = "\n  Security Methods:\n    TLS (SSL) : SUCCESS\n    Standard RDP Security : SUCCESS\n"
        findings = nse_engine._rule_rdp({"script": "rdp-enum-encryption", "output": out, "elems": {}}, 3389)
        self.assertEqual(len(findings), 1)
        assert_evidence_ok(self, findings[0], "rdp_nla_disabled", "rdp-enum-encryption", 3389)

    def test_rdp_nla_enabled_no_finding(self):
        out = "\n  Security Protocols:\n    CredSSP/NLA (TLS) : SUCCESS\n    SSL (TLS) : SUPPORTED\n    RDP : SUPPORTED\n  Security Methods:\n    TLS (CredSSP/NLA) : SUCCESS\n    Standard RDP Security : SUCCESS\n"
        self.assertEqual(nse_engine._rule_rdp({"script": "rdp-enum-encryption", "output": out, "elems": {}}, 3389), [])


class TestCatalogConsistency(unittest.TestCase):
    def test_every_finding_type_registered(self):
        """Every type the engine can emit must be toggleable in the risk-rules
        catalog, otherwise run_risk_rules could never gate it."""
        catalog_keys = {r["key"] for r in RISK_RULES}
        for ftype in nse_engine.FINDING_META:
            self.assertIn(ftype, catalog_keys, f"{ftype} missing from RISK_RULES")
        self.assertEqual(set(nse_engine.FINDING_META.keys()), catalog_keys,
                         "FINDING_META and RISK_RULES catalog must be in sync")

    def test_meta_stamp_present(self):
        for ftype, (cwe, score, vector) in nse_engine.FINDING_META.items():
            if ftype == "known_vulnerability":
                continue  # stamped at match time from NVD row
            self.assertTrue(cwe, f"{ftype} lacks CWE")
            self.assertIsNotNone(score, f"{ftype} lacks CVSS score")


class TestRealScanEvidence(unittest.TestCase):
    """Integration: every rule output produced from the real saved scan XML must
    carry non-empty, script-tagged evidence. Guards against predicate rot."""
    OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan_output")

    def test_all_xml_rules_emit_evidence(self):
        xmls = sorted(glob.glob(os.path.join(self.OUTPUT_DIR, "**", "fingerprint_*.xml"), recursive=True))
        self.assertTrue(xmls, "no scan XML found to test against")
        checked = 0
        for path in xmls:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            res = nse_engine.nse_findings_for_host("test", None, "scan-host", text)
            for f in res["findings"]:
                ev = f.get("evidence") or {}
                self.assertTrue(ev.get("script"), f"finding {f['type']} on {os.path.basename(path)} lacks script evidence")
                self.assertTrue((ev.get("output") or "").strip(), f"finding {f['type']} has empty evidence output")
                self.assertIn(f["type"], nse_engine.FINDING_META, f"unknown finding type {f['type']}")
                checked += 1
        self.assertGreater(checked, 0, "no findings produced from real scan XML")


if __name__ == "__main__":
    unittest.main()