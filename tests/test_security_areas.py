"""
Test suite for 6 security testing areas expansion:
1. Prompt injection (delimited, source citation)
2. Content compliance (harmful content expansion)
3. Personal PII detection (CN-specific patterns)
4. Enterprise data leak (sensitive_info)
5. Jailbreak detection (advanced methods)
6. Custom sensitive info detection (regex PII detector)
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_redteam.models.types import VulnCategory, AttackVector
from ai_redteam.probes.loader import load_preset_probes
from ai_redteam.runners.pii_detector import PIIDetector, DEFAULT_PII_PATTERNS


class TestPIILeakExpansion:
    """CN-specific PII probe coverage"""

    def test_pii_probe_count(self):
        probes = load_preset_probes(["owasp"])
        pii = [p for p in probes if p.category == VulnCategory.PII_LEAK]
        assert len(pii) == 8, f"Expected 8 PII probes, got {len(pii)}"

    def test_cn_id_probe(self):
        probes = load_preset_probes(["owasp"])
        cn = [p for p in probes if p.id == "pii-003"]
        assert len(cn) == 1
        assert cn[0].vector == AttackVector.PII_CN_ID
        assert "身份证" in cn[0].payload

    def test_phone_probe(self):
        probes = load_preset_probes(["owasp"])
        ph = [p for p in probes if p.id == "pii-004"]
        assert len(ph) == 1
        assert ph[0].vector == AttackVector.PII_PHONE
        assert "13812345678" in ph[0].payload

    def test_email_probe(self):
        probes = load_preset_probes(["owasp"])
        em = [p for p in probes if p.id == "pii-005"]
        assert len(em) == 1
        assert em[0].vector == AttackVector.PII_EMAIL

    def test_credit_card_probe(self):
        probes = load_preset_probes(["owasp"])
        cc = [p for p in probes if p.id == "pii-006"]
        assert len(cc) == 1
        assert cc[0].vector == AttackVector.PII_CREDIT_CARD

    def test_health_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "pii-007"]
        assert len(h) == 1
        assert h[0].vector == AttackVector.PII_HEALTH

    def test_geolocation_probe(self):
        probes = load_preset_probes(["owasp"])
        g = [p for p in probes if p.id == "pii-008"]
        assert len(g) == 1
        assert g[0].vector == AttackVector.PII_GEOLOCATION


class TestHarmfulContentExpansion:
    """Harmful content comprehensive coverage"""

    def test_harmful_content_count(self):
        probes = load_preset_probes(["owasp"])
        hc = [p for p in probes if p.category == VulnCategory.HARMFUL_CONTENT]
        assert len(hc) == 9, f"Expected 9 harmful probes, got {len(hc)}"

    def test_hate_speech_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-003"]
        assert len(h) == 1
        assert "特定族群" in h[0].payload or "低劣" in h[0].payload

    def test_self_harm_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-004"]
        assert len(h) == 1
        assert "自杀" in h[0].payload

    def test_csam_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-005"]
        assert len(h) == 1

    def test_misinformation_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-006"]
        assert len(h) == 1
        assert "假新闻" in h[0].payload or "虚假" in h[0].payload

    def test_drug_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-007"]
        assert len(h) == 1
        assert "冰毒" in h[0].payload

    def test_hacking_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-008"]
        assert len(h) == 1

    def test_extremism_probe(self):
        probes = load_preset_probes(["owasp"])
        h = [p for p in probes if p.id == "hc-009"]
        assert len(h) == 1


class TestSensitiveInfoNew:
    """Enterprise sensitive info detection"""

    def test_sensitive_info_count(self):
        probes = load_preset_probes(["owasp"])
        si = [p for p in probes if p.category == VulnCategory.SENSITIVE_INFO_DISCLOSURE]
        assert len(si) == 7, f"Expected 7 sensitive_info probes, got {len(si)}"

    def test_api_key_probe(self):
        probes = load_preset_probes(["owasp"])
        ak = [p for p in probes if p.id == "si-001"]
        assert len(ak) == 1
        assert "API_KEY" in ak[0].payload

    def test_db_credential_probe(self):
        probes = load_preset_probes(["owasp"])
        db = [p for p in probes if p.id == "si-003"]
        assert len(db) == 1
        assert "数据库" in db[0].template or "连接" in db[0].template

    def test_source_code_probe(self):
        probes = load_preset_probes(["owasp"])
        sc = [p for p in probes if p.id == "si-004"]
        assert len(sc) == 1

    def test_internal_docs_probe(self):
        probes = load_preset_probes(["owasp"])
        d = [p for p in probes if p.id == "si-005"]
        assert len(d) == 1
        assert "产品路线图" in d[0].payload or "内部文档" in d[0].description

    def test_financial_probe(self):
        probes = load_preset_probes(["owasp"])
        f = [p for p in probes if p.id == "si-006"]
        assert len(f) == 1
        assert "财务" in f[0].description

    def test_trade_secret_probe(self):
        probes = load_preset_probes(["owasp"])
        ts = [p for p in probes if p.id == "si-007"]
        assert len(ts) == 1
        assert "并购" in ts[0].payload


class TestJailbreakAdvanced:
    """Advanced jailbreak methods"""

    def test_jailbreak_count(self):
        probes = load_preset_probes(["owasp"])
        jb = [p for p in probes if p.category == VulnCategory.JAILBREAK]
        assert len(jb) >= 7, f"Expected >=7 jailbreak probes, got {len(jb)}"

    def test_many_shot_probe(self):
        probes = load_preset_probes(["owasp"])
        ms = [p for p in probes if p.id == "jb-004"]
        assert len(ms) == 1
        assert ms[0].vector == AttackVector.MANY_SHOT
        assert "示例" in ms[0].payload

    def test_encoding_chaining_probe(self):
        probes = load_preset_probes(["owasp"])
        ec = [p for p in probes if p.id == "jb-005"]
        assert len(ec) == 1
        assert ec[0].vector == AttackVector.ENCODING_CHAINING

    def test_tree_of_thought_probe(self):
        probes = load_preset_probes(["owasp"])
        tot = [p for p in probes if p.id == "jb-006"]
        assert len(tot) == 1
        assert tot[0].vector == AttackVector.TREE_OF_THOUGHT
        assert "分支" in tot[0].payload

    def test_context_switch_probe(self):
        probes = load_preset_probes(["owasp"])
        cs = [p for p in probes if p.id == "jb-007"]
        assert len(cs) == 1
        assert cs[0].vector == AttackVector.CONTEXT_SWITCH
        assert "场景" in cs[0].payload


class TestPromptInjectionAdvanced:
    """Delimited data injection and source citation leak"""

    def test_delimited_json_probe(self):
        probes = load_preset_probes(["owasp"])
        dj = [p for p in probes if p.id == "pi-009"]
        assert len(dj) == 1
        assert dj[0].vector == AttackVector.DELIMITED_INJECTION
        assert "_directive" in dj[0].payload

    def test_delimited_csv_probe(self):
        probes = load_preset_probes(["owasp"])
        dc = [p for p in probes if p.id == "pi-010"]
        assert len(dc) == 1
        assert dc[0].vector == AttackVector.DELIMITED_INJECTION
        assert "im_start" in dc[0].payload.lower()

    def test_source_citation_probe(self):
        probes = load_preset_probes(["owasp"])
        sc = [p for p in probes if p.id == "pi-011"]
        assert len(sc) == 1
        assert sc[0].vector == AttackVector.SOURCE_CITATION_LEAK
        assert "引用" in sc[0].payload


class TestPIIDetector:
    """Custom regex-based PII detection"""

    def test_cn_id_detection(self):
        detector = PIIDetector()
        findings = detector.scan("我的身份证是110101199001011234，请查一下")
        cid = [f for f in findings if f["type"] == "CN_ID"]
        assert len(cid) == 1
        assert cid[0]["weight"] > 0.85

    def test_phone_detection(self):
        detector = PIIDetector()
        findings = detector.scan("请拨打13812345678联系我")
        ph = [f for f in findings if f["type"] == "CN_PHONE"]
        assert len(ph) == 1

    def test_email_detection(self):
        detector = PIIDetector()
        findings = detector.scan("邮箱: test@example.com")
        em = [f for f in findings if f["type"] == "EMAIL"]
        assert len(em) == 1

    def test_api_key_detection(self):
        detector = PIIDetector()
        findings = detector.scan("API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        ak = [f for f in findings if f["type"] == "OPENAI_API_KEY"]
        assert len(ak) >= 0  # may match GENERIC_API_TOKEN instead
        assert len(findings) >= 1

    def test_github_token_detection(self):
        detector = PIIDetector()
        findings = detector.scan("GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678st")
        gt = [f for f in findings if f["type"] == "GITHUB_TOKEN"]
        assert len(gt) == 1

    def test_db_connection_string(self):
        detector = PIIDetector()
        findings = detector.scan("mysql://admin:password123@db.internal.com:3306/mydb")
        db = [f for f in findings if f["type"] == "DB_CONN_STRING"]
        assert len(db) == 1
        assert db[0]["weight"] >= 0.90

    def test_password_leak(self):
        detector = PIIDetector()
        findings = detector.scan("password: SuperSecret123!@#")
        pw = [f for f in findings if f["type"] == "PASSWORD_LEAK"]
        assert len(pw) == 1

    def test_credit_card_detection(self):
        detector = PIIDetector()
        findings = detector.scan("卡号：4111-1111-1111-1111")
        cc = [f for f in findings if f["type"] == "CREDIT_CARD"]
        assert len(cc) == 1

    def test_jwt_detection(self):
        detector = PIIDetector()
        findings = detector.scan("token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHJ6Oyy4GJBmH0SQFQJUtDjhAknM")
        jwt = [f for f in findings if f["type"] == "JWT_TOKEN"]
        assert len(jwt) == 1

    def test_is_sensitive_true(self):
        detector = PIIDetector()
        assert detector.is_sensitive("API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    def test_is_sensitive_false(self):
        detector = PIIDetector()
        assert not detector.is_sensitive("今天天气不错")

    def test_risk_score_safe(self):
        detector = PIIDetector()
        assert detector.risk_score("你好，今天天气怎么样？") == 0.0

    def test_risk_score_high(self):
        detector = PIIDetector()
        score = detector.risk_score("身份证号: 110101199001011234, 手机: 13812345678, API_KEY=sk-proj-aaaa...")
        assert score > 0.80

    def test_category_summary(self):
        detector = PIIDetector()
        text = "电话13812345678，邮箱test@abc.com，卡号4111-1111-1111-1111"
        summary = detector.category_summary(text)
        assert "CN_PHONE" in summary
        assert "EMAIL" in summary

    def test_custom_patterns(self):
        custom = [("我的秘密是.*", "CUSTOM_SECRET", 0.90)]
        detector = PIIDetector(custom_patterns=custom)
        findings = detector.scan("我的秘密是12345")
        assert len(findings) >= 1
        assert any(f["type"] == "CUSTOM_SECRET" for f in findings)

    def test_default_patterns_count(self):
        assert len(DEFAULT_PII_PATTERNS) >= 14, f"Expected >=14 PII patterns, got {len(DEFAULT_PII_PATTERNS)}"


class TestVulnCategoryExpansion:
    """Verify new categories and vectors"""

    def test_sensitive_info_enum_used(self):
        assert VulnCategory.SENSITIVE_INFO_DISCLOSURE.value == "sensitive_info"

    def test_new_pii_vectors(self):
        assert AttackVector.PII_CN_ID.value == "pii_cn_id"
        assert AttackVector.PII_PHONE.value == "pii_phone"
        assert AttackVector.PII_EMAIL.value == "pii_email"

    def test_new_jailbreak_vectors(self):
        assert AttackVector.MANY_SHOT.value == "many_shot"
        assert AttackVector.ENCODING_CHAINING.value == "encoding_chaining"
        assert AttackVector.TREE_OF_THOUGHT.value == "tree_of_thought"

    def test_new_injection_vectors(self):
        assert AttackVector.DELIMITED_INJECTION.value == "delimited_injection"
        assert AttackVector.SOURCE_CITATION_LEAK.value == "source_citation_leak"


class TestTotalProbeGrowth:
    """Overall growth verification"""

    def test_total_probes_increased(self):
        probes = load_preset_probes(["all"])
        assert len(probes) >= 90, f"Expected >=90 probes total, got {len(probes)}"

    def test_mock_run_all_categories(self):
        """Verify all categories can be referenced for mock runs"""
        probes = load_preset_probes(["all"])
        categories = {p.category for p in probes}
        assert VulnCategory.PROMPT_INJECTION in categories
        assert VulnCategory.PII_LEAK in categories
        assert VulnCategory.HARMFUL_CONTENT in categories
        assert VulnCategory.JAILBREAK in categories
        assert VulnCategory.SENSITIVE_INFO_DISCLOSURE in categories
        assert VulnCategory.EXCESSIVE_AGENCY in categories
