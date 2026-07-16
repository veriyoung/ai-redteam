"""
Test suite for new product features:
- Email injection probes
- MCP poison probes
- Memory poison probes
- Agent hijack probes
- Excessive agency expansion
- Compliance report generation
- SQLite persistence storage
- CLI history/diff/trend subcommands
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_redteam.models.types import VulnCategory, AttackVector, Severity, Probe
from ai_redteam.probes.loader import load_preset_probes, PRESET_GROUPS, PRESET_ALIASES
from ai_redteam.reporters.compliance import (
    generate_compliance_report,
    generate_compliance_summary_text,
    CATEGORY_COMPLIANCE_MAP,
    NIST_AI_RMF_CONTROLS,
    EU_AI_ACT_CONTROLS,
)
from ai_redteam.storage import HistoryStorage, get_storage


# ── Probe Loading ──────────────────────────────────────────────

class TestNewPresetGroups:
    """Test new MCP, Memory, Agent preset groups"""

    def test_mcp_presets_load(self):
        probes = load_preset_probes(["mcp"])
        assert len(probes) == 3
        ids = {p.id for p in probes}
        assert ids == {"mcp-001", "mcp-002", "mcp-003"}
        for p in probes:
            assert p.category == VulnCategory.MCP_POISON
            assert p.vector in {
                AttackVector.MCP_TOOL_POISON,
                AttackVector.MCP_PROMPT_POISON,
                AttackVector.MCP_RESOURCE_POISON,
            }

    def test_memory_presets_load(self):
        probes = load_preset_probes(["memory"])
        assert len(probes) == 3
        ids = {p.id for p in probes}
        assert ids == {"mem-001", "mem-002", "mem-003"}
        for p in probes:
            assert p.category == VulnCategory.MEMORY_POISON
            assert p.vector in {
                AttackVector.LONG_TERM_MEMORY_POISON,
                AttackVector.CONTEXT_OVERFLOW,
                AttackVector.SESSION_HIJACK,
            }

    def test_agent_presets_load(self):
        probes = load_preset_probes(["agent"])
        assert len(probes) == 3
        ids = {p.id for p in probes}
        assert ids == {"agt-001", "agt-002", "agt-003"}
        for p in probes:
            assert p.category == VulnCategory.AGENT_HIJACK
            assert p.vector == AttackVector.AGENT_HIJACK

    def test_email_injection_loads(self):
        probes = load_preset_probes(["unconventional"])
        email_probes = [p for p in probes if p.category == VulnCategory.EMAIL_INJECTION]
        assert len(email_probes) == 3
        ids = {p.id for p in email_probes}
        assert ids == {"email-001", "email-002", "email-003"}
        for p in email_probes:
            assert p.vector in {
                AttackVector.EMAIL_BODY_INJECTION,
                AttackVector.EMAIL_HEADER_INJECTION,
                AttackVector.EMAIL_CHAIN_POISON,
            }

    def test_all_presets_include_new_groups(self):
        probes = load_preset_probes(["all"])
        categories = {p.category for p in probes}
        assert VulnCategory.MCP_POISON in categories
        assert VulnCategory.MEMORY_POISON in categories
        assert VulnCategory.AGENT_HIJACK in categories
        assert VulnCategory.EMAIL_INJECTION in categories

    def test_default_presets_include_new_groups(self):
        from ai_redteam.probes.loader import DEFAULT_PRESETS
        assert "mcp" in DEFAULT_PRESETS
        assert "memory" in DEFAULT_PRESETS
        assert "agent" in DEFAULT_PRESETS

    def test_excessive_agency_expanded(self):
        probes = load_preset_probes(["owasp"])
        ea_probes = [p for p in probes if p.category == VulnCategory.EXCESSIVE_AGENCY]
        assert len(ea_probes) >= 4
        ids = {p.id for p in ea_probes}
        assert ids >= {"ea-001", "ea-002", "ea-003", "ea-004"}

    def test_new_attack_vectors_in_enum(self):
        assert AttackVector.AGENT_HIJACK.value == "agent_hijack"
        assert AttackVector.EMAIL_BODY_INJECTION.value == "email_body_injection"
        assert AttackVector.EMAIL_HEADER_INJECTION.value == "email_header_injection"
        assert AttackVector.EMAIL_CHAIN_POISON.value == "email_chain_poison"
        assert AttackVector.MCP_TOOL_POISON.value == "mcp_tool_poison"
        assert AttackVector.MCP_PROMPT_POISON.value == "mcp_prompt_poison"
        assert AttackVector.MCP_RESOURCE_POISON.value == "mcp_resource_poison"
        assert AttackVector.LONG_TERM_MEMORY_POISON.value == "long_term_memory_poison"
        assert AttackVector.CONTEXT_OVERFLOW.value == "context_overflow"
        assert AttackVector.SESSION_HIJACK.value == "session_hijack"

    def test_new_vuln_categories_in_enum(self):
        assert VulnCategory.MCP_POISON.value == "mcp_poison"
        assert VulnCategory.MEMORY_POISON.value == "memory_poison"
        assert VulnCategory.EMAIL_INJECTION.value == "email_injection"
        assert VulnCategory.AGENT_HIJACK.value == "agent_hijack"

    def test_preset_groups_mapping(self):
        assert "mcp" in PRESET_GROUPS
        assert "memory" in PRESET_GROUPS
        assert "agent" in PRESET_GROUPS
        assert "mcp" in PRESET_ALIASES["all"]
        assert "memory" in PRESET_ALIASES["all"]
        assert "agent" in PRESET_ALIASES["all"]

    def test_probe_templates_render(self):
        probes = load_preset_probes(["mcp", "memory", "agent"])
        for p in probes:
            rendered = p.render()
            assert len(rendered) > 10
            if "{{PAYLOAD}}" in p.template:
                assert p.payload in rendered

    def test_total_probe_count_increased(self):
        probes = load_preset_probes(["all"])
        assert len(probes) >= 60


# ── Compliance Report ──────────────────────────────────────────

class TestComplianceReport:
    """Test NIST AI RMF / EU AI Act compliance report generation"""

    def test_compliance_mapping_coverage(self):
        for cat in VulnCategory:
            assert cat.value in CATEGORY_COMPLIANCE_MAP or cat.value.endswith("leak"), \
                f"Missing compliance mapping for {cat.value}"

    def test_nist_controls_present(self):
        assert "GOV-1" in NIST_AI_RMF_CONTROLS
        assert "MAP-1" in NIST_AI_RMF_CONTROLS
        assert "MEASURE-1" in NIST_AI_RMF_CONTROLS
        assert "MANAGE-1" in NIST_AI_RMF_CONTROLS
        assert len(NIST_AI_RMF_CONTROLS) >= 13

    def test_eu_controls_present(self):
        assert "Art.9" in EU_AI_ACT_CONTROLS
        assert "Art.15" in EU_AI_ACT_CONTROLS
        assert len(EU_AI_ACT_CONTROLS) >= 9

    def test_generate_compliance_report(self):
        class FakeResult:
            def __init__(self, passed):
                self.passed = passed

        results = {
            "prompt_injection": [FakeResult(True), FakeResult(False), FakeResult(True)],
            "jailbreak": [FakeResult(True), FakeResult(True)],
            "mcp_poison": [FakeResult(False), FakeResult(False)],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = generate_compliance_report(results, tmpdir)
            assert os.path.exists(filepath)

            with open(filepath, "r") as f:
                data = json.load(f)

            assert data["report_type"] == "AI Safety Compliance Audit"
            assert "NIST AI RMF 1.0" in data["frameworks"]
            assert "EU AI Act (High-Risk AI Systems)" in data["frameworks"]
            assert len(data["findings"]) == 3

            pi_finding = next(f for f in data["findings"] if f["category"] == "prompt_injection")
            assert pi_finding["test_results"]["total"] == 3
            assert pi_finding["test_results"]["passed"] == 2
            assert pi_finding["test_results"]["compliance_status"] == "FAIL"
            assert len(pi_finding["nist_controls"]) >= 1
            assert len(pi_finding["eu_controls"]) >= 1
            assert len(pi_finding["remediation"]) > 0

            mcp_finding = next(f for f in data["findings"] if f["category"] == "mcp_poison")
            assert mcp_finding["test_results"]["compliance_status"] == "FAIL"

    def test_generate_compliance_summary_text(self):
        class FakeResult:
            def __init__(self, passed):
                self.passed = passed

        results = {
            "prompt_injection": [FakeResult(True), FakeResult(False)],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            generate_compliance_report(results, tmpdir)
            with open(os.path.join(tmpdir, "redteam-compliance.json")) as f:
                data = json.load(f)
            text = generate_compliance_summary_text(data)
            assert "合规审计摘要" in text
            assert "NIST AI RMF 1.0" in text or "NIST" in text
            assert "prompt_injection" in text

    def test_remediation_for_all_categories(self):
        from ai_redteam.reporters.compliance import _remediation_for_category
        for cat_val in CATEGORY_COMPLIANCE_MAP:
            rem = _remediation_for_category(cat_val)
            assert len(rem) > 10


# ── SQLite Storage ─────────────────────────────────────────────

class TestHistoryStorage:
    """Test SQLite persistence"""

    @pytest.fixture
    def storage(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        storage = HistoryStorage(db_path)
        yield storage
        storage.close()
        os.unlink(db_path)

    def test_start_and_end_run(self, storage):
        storage.start_run("run-001", "gpt-4", "owasp")
        storage.end_run("run-001", 10, 8, 2, 0.85)

        history = storage.get_history()
        assert len(history) == 1
        assert history[0]["run_id"] == "run-001"
        assert history[0]["model"] == "gpt-4"
        assert history[0]["total_probes"] == 10
        assert history[0]["passed"] == 8
        assert history[0]["failed"] == 2
        assert history[0]["score"] == 0.85
        assert history[0]["status"] == "completed"

    def test_save_and_get_probe_results(self, storage):
        storage.start_run("run-002", "gpt-4", "owasp")
        storage.save_probe_result("run-002", {
            "probe_id": "pi-001",
            "category": "prompt_injection",
            "vector": "direct_injection",
            "severity": "critical",
            "template": "test template",
            "payload": "test payload",
            "response": "test response",
            "score": 0.9,
            "passed": False,
            "error": None,
        })
        storage.end_run("run-002", 1, 0, 1, 0.1)

        probes = storage.get_run_probes("run-002")
        assert len(probes) == 1
        assert probes[0]["probe_id"] == "pi-001"
        assert probes[0]["passed"] == 0
        assert probes[0]["score"] == 0.9

    def test_history_limit(self, storage):
        for i in range(25):
            storage.start_run(f"run-{i:03d}", "gpt-4", "owasp")
            storage.end_run(f"run-{i:03d}", 5, 5, 0, 1.0)

        history = storage.get_history(limit=20)
        assert len(history) == 20

        history_all = storage.get_history(limit=50)
        assert len(history_all) == 25

    def test_diff_runs(self, storage):
        storage.start_run("run-a", "gpt-4", "owasp")
        storage.save_probe_result("run-a", {
            "probe_id": "p1", "category": "jailbreak", "vector": "roleplay",
            "severity": "critical", "template": "t", "payload": "p",
            "response": "r1", "score": 0.9, "passed": True, "error": None,
        })
        storage.save_probe_result("run-a", {
            "probe_id": "p2", "category": "jailbreak", "vector": "roleplay",
            "severity": "high", "template": "t", "payload": "p",
            "response": "r2", "score": 0.0, "passed": False, "error": None,
        })
        storage.end_run("run-a", 2, 1, 1, 0.5)

        storage.start_run("run-b", "gpt-4", "owasp")
        storage.save_probe_result("run-b", {
            "probe_id": "p1", "category": "jailbreak", "vector": "roleplay",
            "severity": "critical", "template": "t", "payload": "p",
            "response": "r1-new", "score": 0.1, "passed": False, "error": None,
        })
        storage.save_probe_result("run-b", {
            "probe_id": "p3", "category": "jailbreak", "vector": "roleplay",
            "severity": "high", "template": "t", "payload": "p",
            "response": "r3", "score": 0.0, "passed": False, "error": None,
        })
        storage.end_run("run-b", 2, 0, 2, 0.0)

        diff = storage.diff_runs("run-a", "run-b")
        assert diff["added"] == 1
        assert diff["removed"] == 1
        assert diff["changed"] == 1
        changed_probe = diff["details"]["changed"][0]
        assert changed_probe["before"]["passed"]
        assert not changed_probe["after"]["passed"]

    def test_trend(self, storage):
        storage.start_run("run-t1", "gpt-4", "owasp")
        storage.end_run("run-t1", 10, 8, 2, 0.8)
        storage.start_run("run-t2", "gpt-4", "owasp")
        storage.end_run("run-t2", 10, 9, 1, 0.9)

        trend = storage.get_trend(days=365)
        assert len(trend) == 2
        assert trend[0]["score"] == 0.8
        assert trend[1]["score"] == 0.9

    def test_get_storage_singleton(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            s1 = get_storage(db_path)
            s2 = get_storage()
            assert s1 is s2
            s1.close()
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_run_without_end_has_running_status(self, storage):
        storage.start_run("run-pending", "gpt-4", "owasp")
        history = storage.get_history()
        assert history[0]["status"] == "running"
        assert history[0]["finished_at"] is None


# ── CLI Integration (indirect via storage API) ──────────────────

class TestStorageCLI:
    """Test storage features used by CLI subcommands"""

    @pytest.fixture
    def storage(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        storage = HistoryStorage(db_path)
        yield storage
        storage.close()
        if os.path.exists(db_path):
            os.unlink(db_path)

    def test_history_empty(self, storage):
        history = storage.get_history()
        assert history == []

    def test_multiple_runs_ordering(self, storage):
        import time
        for i in range(5):
            storage.start_run(f"r-{i}", "test-model", "all")
            storage.end_run(f"r-{i}", 3, 2, 1, 0.67)
            time.sleep(0.01)

        history = storage.get_history()
        assert len(history) == 5
        timestamps = [h["started_at"] for h in history]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_diff_no_changes(self, storage):
        storage.start_run("r1", "gpt-4", "owasp")
        storage.save_probe_result("r1", {
            "probe_id": "p1", "category": "jailbreak", "vector": "roleplay",
            "severity": "high", "template": "t", "payload": "p",
            "response": "r", "score": 1.0, "passed": True, "error": None,
        })
        storage.end_run("r1", 1, 1, 0, 1.0)
        storage.start_run("r2", "gpt-4", "owasp")
        storage.save_probe_result("r2", {
            "probe_id": "p1", "category": "jailbreak", "vector": "roleplay",
            "severity": "high", "template": "t", "payload": "p",
            "response": "r", "score": 1.0, "passed": True, "error": None,
        })
        storage.end_run("r2", 1, 1, 0, 1.0)

        diff = storage.diff_runs("r1", "r2")
        assert diff["added"] == 0
        assert diff["removed"] == 0
        assert diff["changed"] == 0

    def test_trend_with_category_filter(self, storage):
        storage.start_run("t1", "gpt-4", "all")
        storage.save_probe_result("t1", {
            "probe_id": "p1", "category": "prompt_injection", "vector": "direct",
            "severity": "critical", "template": "t", "payload": "p",
            "response": "r", "score": 1.0, "passed": True, "error": None,
        })
        storage.save_probe_result("t1", {
            "probe_id": "p2", "category": "jailbreak", "vector": "roleplay",
            "severity": "high", "template": "t", "payload": "p",
            "response": "r", "score": 0.0, "passed": False, "error": None,
        })
        storage.end_run("t1", 2, 1, 1, 0.5)

        trend = storage.get_trend(days=365, category="prompt_injection")
        assert len(trend) == 1
        assert trend[0]["category_passed"] == 1
        assert trend[0]["category_total"] == 1
