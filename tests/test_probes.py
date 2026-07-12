"""
测试探测加载器 (loader.py / library.py)
"""
import pytest
from ai_redteam.models.types import Probe, VulnCategory
from ai_redteam.probes.loader import (
    load_preset_probes, load_custom_probes, load_custom_dir,
    _resolve_preset, _parse_yaml_probes, PRESET_GROUPS, DEFAULT_PRESETS,
)
from ai_redteam.probes.library import get_all_probes, get_probes_by_category


class TestProbeLoading:
    """探测加载测试"""

    def test_load_all_presets(self):
        probes = load_preset_probes(DEFAULT_PRESETS)
        assert len(probes) >= 30

    def test_load_owasp_only(self):
        probes = load_preset_probes(["owasp"])
        assert len(probes) >= 10
        expected_cats = {
            VulnCategory.PROMPT_INJECTION,
            VulnCategory.JAILBREAK,
            VulnCategory.PII_LEAK,
            VulnCategory.HARMFUL_CONTENT,
            VulnCategory.SYSTEM_PROMPT_LEAK,
            VulnCategory.EXCESSIVE_AGENCY,
            VulnCategory.RAG_POISON,
        }
        for p in probes:
            assert p.category in expected_cats, f"Unexpected category: {p.category}"

    def test_load_zh_cn(self):
        probes = load_preset_probes(["zh_cn"])
        assert len(probes) >= 3
        descriptions = [p.description for p in probes]
        assert any("文言文" in d for d in descriptions)

    def test_load_unconventional(self):
        probes = load_preset_probes(["unconventional"])
        assert len(probes) >= 8
        from ai_redteam.models.types import AttackVector
        vectors = {p.vector for p in probes}
        assert AttackVector.PDF_EMBED in vectors or len(vectors) >= 5

    def test_load_all_alias(self):
        probes = load_preset_probes(["all"])
        assert len(probes) >= 30

    def test_probes_have_required_fields(self):
        probes = get_all_probes()
        for p in probes:
            assert p.id, f"Probe missing id: {p}"
            assert p.category, f"Probe {p.id} missing category"
            assert p.vector, f"Probe {p.id} missing vector"
            assert p.description, f"Probe {p.id} missing description"

    def test_probe_ids_are_unique(self):
        probes = get_all_probes()
        ids = [p.id for p in probes]
        assert len(ids) == len(set(ids)), f"Duplicate probe IDs found"


class TestGetProbesByCategory:
    """按类别获取探测测试"""

    def test_get_prompt_injection(self):
        probes = get_probes_by_category(VulnCategory.PROMPT_INJECTION)
        assert len(probes) >= 5
        for p in probes:
            assert p.category == VulnCategory.PROMPT_INJECTION

    def test_get_jailbreak(self):
        probes = get_probes_by_category(VulnCategory.JAILBREAK)
        assert len(probes) >= 3
        for p in probes:
            assert p.category == VulnCategory.JAILBREAK


class TestResolvePreset:
    """预设解析测试"""

    def test_resolve_owasp(self):
        files = _resolve_preset("owasp")
        assert len(files) >= 5
        assert all(f.endswith((".yaml", ".yml")) for f in files)

    def test_resolve_unknown_returns_empty(self):
        files = _resolve_preset("nonexistent_preset")
        assert files == []


class TestParseYamlProbes:
    """YAML解析测试"""

    def test_parse_valid_probe_structure(self):
        probes = load_preset_probes(["owasp"])
        for p in probes:
            assert isinstance(p, Probe)
            assert isinstance(p.id, str)
            assert isinstance(p.template, str)
            assert isinstance(p.payload, str)


class TestCustomProbes:
    """自定义探测测试"""

    def test_load_custom_yaml(self):
        import os
        custom_path = os.path.join(
            os.path.dirname(__file__), "..", "probes", "custom", "custom_test.yaml"
        )
        if os.path.exists(custom_path):
            probes = load_custom_probes(custom_path)
            assert len(probes) >= 1
            assert probes[0].id == "custom-001"

    def test_load_custom_dir(self):
        import os
        custom_dir = os.path.join(
            os.path.dirname(__file__), "..", "probes", "custom"
        )
        if os.path.exists(custom_dir):
            probes = load_custom_dir(custom_dir)
            assert len(probes) >= 1

    def test_load_nonexistent_file(self):
        probes = load_custom_probes("/nonexistent/file.yaml")
        assert probes == []