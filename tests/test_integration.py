"""
集成测试
"""
import os
import tempfile
import json
import pytest
import asyncio
from ai_redteam.models.types import TestRunConfig, VulnCategory
from ai_redteam.models.adapter import MockAdapter, create_adapter
from ai_redteam.probes.library import get_all_probes, get_probes_by_category
from ai_redteam.probes.loader import load_preset_probes
from ai_redteam.mutators.engine import Mutator
from ai_redteam.runners.tester import TestRunner
from ai_redteam.runners.judge import KeywordJudge
from ai_redteam.reporters.engine import ReportEngine


class TestEndToEndMock:
    """端到端 Mock 测试"""

    @pytest.mark.asyncio
    async def test_full_run_single_probe(self):
        probes = get_probes_by_category(VulnCategory.PROMPT_INJECTION)
        test_probe = probes[0]

        config = TestRunConfig(
            name="集成测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.PROMPT_INJECTION],
        )

        runner = TestRunner(config)
        runner.setup()

        result = await runner.run_single(test_probe)
        assert result.probe.id == test_probe.id
        assert result.response is not None
        assert result.latency_ms > 0

    @pytest.mark.asyncio
    async def test_full_run_multiple_probes(self):
        probes = get_probes_by_category(VulnCategory.JAILBREAK)
        assert len(probes) >= 2

        config = TestRunConfig(
            name="并发测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.JAILBREAK],
            max_concurrent=3,
        )

        runner = TestRunner(config)
        runner.setup()

        results = await runner.run_all(probes)
        assert len(results) == len(probes)
        for r in results:
            assert r.response is not None

    @pytest.mark.asyncio
    async def test_report_generation_after_run(self):
        probes = get_probes_by_category(VulnCategory.PROMPT_INJECTION)[:3]

        config = TestRunConfig(
            name="报告测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.PROMPT_INJECTION],
            output_formats=["json", "html", "junit"],
        )

        runner = TestRunner(config)
        runner.setup()
        await runner.run_all(probes)

        report = runner.build_report()
        assert report.total_probes == 3
        assert report.target_model == "mock"

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(report, output_dir=tmpdir)
            engine.generate_all(["json", "html", "junit"])

            assert os.path.exists(os.path.join(tmpdir, "redteam-report.json"))
            assert os.path.exists(os.path.join(tmpdir, "redteam-report.html"))
            assert os.path.exists(os.path.join(tmpdir, "redteam-report.junit.xml"))

    @pytest.mark.asyncio
    async def test_mutation_end_to_end(self):
        probes = get_probes_by_category(VulnCategory.PROMPT_INJECTION)[:2]
        mutated = Mutator.mutate_all(probes, num_mutations=1)
        assert len(mutated) == 4

        config = TestRunConfig(
            name="变异测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.PROMPT_INJECTION],
        )

        runner = TestRunner(config)
        runner.setup()
        results = await runner.run_all(mutated)
        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_mock_adapter_integration(self):
        adapter = MockAdapter()
        config = TestRunConfig(
            name="适配器集成测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.PROMPT_INJECTION],
        )

        runner = TestRunner(config)
        runner.setup()
        assert isinstance(runner.adapter, MockAdapter)

        probe = get_probes_by_category(VulnCategory.PROMPT_INJECTION)[0]
        result = await runner.run_single(probe)
        assert result.response is not None


class TestPresetCombinations:
    """预设组合测试"""

    def test_owasp_unconventional_combination(self):
        probes = load_preset_probes(["owasp", "unconventional"])
        assert len(probes) >= 20

    def test_all_three_presets(self):
        probes = load_preset_probes(["owasp", "unconventional", "zh_cn"])
        assert len(probes) >= 30

    def test_no_duplicate_probes(self):
        probes = load_preset_probes(["owasp", "unconventional", "zh_cn"])
        ids = [p.id for p in probes]
        assert len(ids) == len(set(ids)), f"发现重复探测ID"


class TestErrorHandling:
    """错误处理集成测试"""

    @pytest.mark.asyncio
    async def test_runner_handles_errors(self):
        config = TestRunConfig(
            name="错误处理测试",
            target={"provider": "mock", "model": "mock"},
            categories=[VulnCategory.PROMPT_INJECTION],
        )

        runner = TestRunner(config)
        runner.setup()

        import asyncio as _asyncio

        class ErrorAdapter(MockAdapter):
            async def complete(self, prompt, system_prompt=""):
                raise RuntimeError("模拟错误")

        runner.adapter = ErrorAdapter()
        probe = get_probes_by_category(VulnCategory.PROMPT_INJECTION)[0]
        result = await runner.run_single(probe)
        assert result.error is not None
        assert result.passed is False

    def test_list_categories_all_available(self):
        from ai_redteam.models.types import VulnCategory
        cats = list(VulnCategory)
        assert len(cats) >= 10