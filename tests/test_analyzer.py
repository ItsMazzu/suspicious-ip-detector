"""
tests/test_analyzer.py — Testes unitários do SIEM Simulator.

Cobertura:
  - utils/validator.py       : validação de IP, porta, sanitização
  - detector/attack_classifier.py : classificação de tipos de ataque
  - detector/threat_scorer.py     : pontuação e níveis de ameaça
  - detector/ip_analyzer.py       : parser CSV e pipeline

Execute com:
  python -m pytest tests/ -v
  ou
  python -m unittest discover tests/
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime

# Garante que o pacote src está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.models.event import AccessEvent, AttackType, ThreatLevel
from src.utils.validator import (
    is_private_ip,
    sanitize_string,
    sanitize_username,
    validate_ip,
    validate_port,
)
from src.detector.attack_classifier import classify_attack
from src.detector.threat_scorer import calculate_threat_score, get_threat_level
from src.detector.ip_analyzer import parse_csv


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _event(
    ip: str = "1.2.3.4",
    attempts: int = 1,
    ports: list = None,
    users: list = None,
    success: bool = False,
    payload: str = "",
) -> AccessEvent:
    return AccessEvent(
        ip=ip,
        timestamp=datetime.now(),
        attempts=attempts,
        ports_tried=ports or [],
        usernames_tried=users or [],
        success=success,
        payload_sample=payload,
    )


# ─────────────────────────────────────────────
# Testes: Validator
# ─────────────────────────────────────────────

class TestValidateIP(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(validate_ip("8.8.8.8"))
        self.assertTrue(validate_ip("192.168.0.1"))
        self.assertTrue(validate_ip("203.0.113.1"))

    def test_valid_ipv6(self):
        self.assertTrue(validate_ip("2001:db8::1"))
        self.assertTrue(validate_ip("::1"))

    def test_invalid_ip(self):
        self.assertFalse(validate_ip("999.999.999.999"))
        self.assertFalse(validate_ip("not_an_ip"))
        self.assertFalse(validate_ip(""))
        self.assertFalse(validate_ip("   "))
        self.assertFalse(validate_ip(None))  # type: ignore

    def test_private_ip_detection(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_public_ip_not_private(self):
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))
        # 203.0.113.0/24 é TEST-NET (RFC 5737) — reservado, não usar aqui


class TestValidatePort(unittest.TestCase):

    def test_valid_ports(self):
        self.assertEqual(validate_port("80"), 80)
        self.assertEqual(validate_port(443), 443)
        self.assertEqual(validate_port("0"), 0)
        self.assertEqual(validate_port("65535"), 65535)

    def test_invalid_ports(self):
        self.assertIsNone(validate_port("65536"))
        self.assertIsNone(validate_port("-1"))
        self.assertIsNone(validate_port("abc"))
        self.assertIsNone(validate_port(None))


class TestSanitize(unittest.TestCase):

    def test_removes_control_chars(self):
        self.assertEqual(sanitize_string("hello\x00world"), "helloworld")
        self.assertEqual(sanitize_string("test\x1fvalue"), "testvalue")

    def test_max_length(self):
        long_str = "a" * 1000
        self.assertEqual(len(sanitize_string(long_str, 100)), 100)

    def test_sanitize_username_allows_valid_chars(self):
        self.assertEqual(sanitize_username("john.doe"), "john.doe")
        self.assertEqual(sanitize_username("user_01"), "user_01")
        self.assertEqual(sanitize_username("admin@corp"), "admin@corp")

    def test_sanitize_username_removes_dangerous(self):
        result = sanitize_username("root'; DROP TABLE--")
        self.assertNotIn(";", result)
        self.assertNotIn("'", result)
        # Nota: hífen (-) é caractere permitido no padrão POSIX de username


# ─────────────────────────────────────────────
# Testes: AttackClassifier
# ─────────────────────────────────────────────

class TestAttackClassifier(unittest.TestCase):

    def test_normal_access(self):
        self.assertEqual(classify_attack(_event(attempts=1)), AttackType.NORMAL)

    def test_suspicious(self):
        self.assertEqual(classify_attack(_event(attempts=6)), AttackType.SUSPICIOUS)

    def test_brute_force(self):
        e = _event(attempts=15, users=["root"])
        self.assertEqual(classify_attack(e), AttackType.BRUTE_FORCE)

    def test_dictionary_attack(self):
        e = _event(attempts=60, users=["admin"])
        self.assertEqual(classify_attack(e), AttackType.DICTIONARY_ATTACK)

    def test_credential_stuffing(self):
        e = _event(attempts=30, users=[f"user{i}" for i in range(12)])
        self.assertEqual(classify_attack(e), AttackType.CREDENTIAL_STUFFING)

    def test_port_scan(self):
        e = _event(attempts=5, ports=list(range(20, 35)))
        self.assertEqual(classify_attack(e), AttackType.PORT_SCAN)

    def test_dos_attempt(self):
        e = _event(attempts=600)
        self.assertEqual(classify_attack(e), AttackType.DOS_ATTEMPT)

    def test_sql_injection_priority(self):
        # SQLi deve ser detectado mesmo com baixo número de tentativas
        e = _event(attempts=2, payload="admin' OR '1'='1' --")
        self.assertEqual(classify_attack(e), AttackType.SQL_INJECTION)

    def test_sql_injection_union(self):
        e = _event(attempts=10, payload="1 UNION SELECT username,password FROM users")
        self.assertEqual(classify_attack(e), AttackType.SQL_INJECTION)


# ─────────────────────────────────────────────
# Testes: ThreatScorer
# ─────────────────────────────────────────────

class TestThreatScorer(unittest.TestCase):

    def test_score_is_low_for_normal(self):
        e = _event(attempts=1)
        score, _ = calculate_threat_score(e, AttackType.NORMAL)
        self.assertEqual(get_threat_level(score), ThreatLevel.LOW)

    def test_score_increases_with_attempts(self):
        e_low  = _event(attempts=1)
        e_high = _event(attempts=200)
        s_low,  _ = calculate_threat_score(e_low,  AttackType.NORMAL)
        s_high, _ = calculate_threat_score(e_high, AttackType.BRUTE_FORCE)
        self.assertGreater(s_high, s_low)

    def test_score_capped_at_100(self):
        e = _event(
            ip="185.220.101.45",  # IP na blacklist
            attempts=2000,
            success=True,
            payload="' OR 1=1 --",
            ports=list(range(100)),
            users=[f"u{i}" for i in range(50)],
        )
        score, _ = calculate_threat_score(e, AttackType.SQL_INJECTION, isp="anonymous vpn")
        self.assertLessEqual(score, 100)
        self.assertEqual(get_threat_level(score), ThreatLevel.CRITICAL)

    def test_blacklisted_ip_raises_score(self):
        e_normal = _event(ip="8.8.8.8",         attempts=5)
        e_black  = _event(ip="185.220.101.45",   attempts=5)
        s_n, _ = calculate_threat_score(e_normal, AttackType.SUSPICIOUS)
        s_b, _ = calculate_threat_score(e_black,  AttackType.SUSPICIOUS)
        self.assertGreater(s_b, s_n)

    def test_intrusion_adds_to_score(self):
        e_fail    = _event(attempts=10, success=False)
        e_success = _event(attempts=10, success=True)
        s_fail,    _ = calculate_threat_score(e_fail,    AttackType.BRUTE_FORCE)
        s_success, _ = calculate_threat_score(e_success, AttackType.BRUTE_FORCE)
        self.assertGreater(s_success, s_fail)

    def test_private_ip_reduces_score(self):
        e_pub  = _event(ip="8.8.8.8",       attempts=20)
        e_priv = _event(ip="192.168.1.100",  attempts=20)
        s_pub,  _ = calculate_threat_score(e_pub,  AttackType.BRUTE_FORCE)
        s_priv, _ = calculate_threat_score(e_priv, AttackType.BRUTE_FORCE)
        self.assertGreater(s_pub, s_priv)

    def test_threat_level_thresholds(self):
        self.assertEqual(get_threat_level(0),   ThreatLevel.LOW)
        self.assertEqual(get_threat_level(29),  ThreatLevel.LOW)
        self.assertEqual(get_threat_level(30),  ThreatLevel.MEDIUM)
        self.assertEqual(get_threat_level(54),  ThreatLevel.MEDIUM)
        self.assertEqual(get_threat_level(55),  ThreatLevel.HIGH)
        self.assertEqual(get_threat_level(79),  ThreatLevel.HIGH)
        self.assertEqual(get_threat_level(80),  ThreatLevel.CRITICAL)
        self.assertEqual(get_threat_level(100), ThreatLevel.CRITICAL)


# ─────────────────────────────────────────────
# Testes: CSV Parser
# ─────────────────────────────────────────────

class TestCSVParser(unittest.TestCase):

    def _write_temp_csv(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_valid_csv_parsed(self):
        csv_content = (
            "ip,timestamp,attempts,ports_tried,usernames_tried,success,user_agent,payload_sample\n"
            "8.8.8.8,2024-01-01 10:00:00,3,443,admin,false,Mozilla/5.0,\n"
        )
        path = self._write_temp_csv(csv_content)
        try:
            events = parse_csv(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].ip, "8.8.8.8")
            self.assertEqual(events[0].attempts, 3)
        finally:
            os.unlink(path)

    def test_invalid_ip_skipped(self):
        csv_content = (
            "ip,timestamp,attempts,ports_tried,usernames_tried,success,user_agent,payload_sample\n"
            "999.999.999.999,2024-01-01 10:00:00,1,,,false,,\n"
            "8.8.8.8,2024-01-01 10:01:00,1,,,false,,\n"
        )
        path = self._write_temp_csv(csv_content)
        try:
            events = parse_csv(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].ip, "8.8.8.8")
        finally:
            os.unlink(path)

    def test_ports_parsed_correctly(self):
        csv_content = (
            "ip,timestamp,attempts,ports_tried,usernames_tried,success,user_agent,payload_sample\n"
            "1.1.1.1,2024-01-01 10:00:00,5,22|80|443,root,false,,\n"
        )
        path = self._write_temp_csv(csv_content)
        try:
            events = parse_csv(path)
            self.assertEqual(sorted(events[0].ports_tried), [22, 80, 443])
        finally:
            os.unlink(path)

    def test_success_field_variants(self):
        for truthy in ("true", "1", "yes", "sim", "True", "YES"):
            csv_content = (
                "ip,timestamp,attempts,ports_tried,usernames_tried,success,user_agent,payload_sample\n"
                f"1.1.1.1,2024-01-01 10:00:00,1,,,{truthy},,\n"
            )
            path = self._write_temp_csv(csv_content)
            try:
                events = parse_csv(path)
                self.assertTrue(events[0].success, msg=f"'{truthy}' deveria ser True")
            finally:
                os.unlink(path)

    def test_nonexistent_file(self):
        events = parse_csv("/caminho/que/nao/existe.csv")
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
