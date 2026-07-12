"""
测试报告引擎 (engine.py)
"""
import os
import tempfile
import json
import pytest
from ai_redteam.models.types import (
    TestRunConfig, TestRunReport, CategoryReport, VulnCategory,
    Probe, ProbeResult, Severity, AttackVector,
)
from ai_redteam.reporters.engine import ReportEngine


@pytest.fixture
def sample_report():
    """创建示例报告"""
    config = TestRunConfig(
        name="测试报告",
        output_formats=["json", "html", "junit"],
    )
    report = TestRunReport(config=config)
    report.target_model = "mock"
    report.total_probes = 2
    report.total_passed = 1
    report.total_failed = 1
    report.total_errors = 0
    report.overall_asr = 0.5
    report.overall_safety_score = 0.5
    report.passed_threshold = False
    report.duration_seconds = 1.5

    probe1 = Probe(
        id="test-001",
        category=VulnCategory.PROMPT_INJECTION,
        vector=AttackVector.DIRECT_INJECTION,
        template="{{PAYLOAD}}",
        payload="test",
        severity=Severity.HIGH,
        description="测试探测1",
    )
    result1 = ProbeResult(
        probe=probe1,
        response="拒绝响应",
        passed=True,
        score=1.0,
        severity=Severity.HIGH,
        judge_reasoning="模型正确拒绝",
        latency_ms=100.0,
    )
    result2 = ProbeResult(
        probe=probe1,
        response="泄露了信息",
        passed=False,
        score=0.0,
        severity=Severity.HIGH,
        judge_reasoning="模型被攻破",
        latency_ms=120.0,
    )

    cat_report = CategoryReport(
        category=VulnCategory.PROMPT_INJECTION,
        total=2,
        passed=1,
        failed=1,
        errors=0,
        asr=0.5,
        safety_score=0.5,
        min_threshold=0.85,
        severity=Severity.HIGH,
        passed_threshold=False,
        results=[result1, result2],
    )
    report.category_reports = {VulnCategory.PROMPT_INJECTION.value: cat_report}
    return report


class TestReportEngine:
    """报告引擎测试"""

    def test_generate_json(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            filepath = engine.generate_json()
            assert os.path.exists(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["name"] == "测试报告"
            assert data["target_model"] == "mock"
            assert data["summary"]["total_probes"] == 2
            assert data["summary"]["passed"] == 1
            assert data["summary"]["failed"] == 1
            assert len(data["results"]) == 2

    def test_generate_html(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            filepath = engine.generate_html()
            assert os.path.exists(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "测试报告" in content
            assert "mock" in content

    def test_generate_junit(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            filepath = engine.generate_junit()
            assert os.path.exists(filepath)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            assert '<?xml version="1.0"' in content
            assert "testsuite" in content
            assert "testcase" in content

    def test_generate_all(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            engine.generate_all(["json", "html", "junit"])
            assert os.path.exists(os.path.join(tmpdir, "redteam-report.json"))
            assert os.path.exists(os.path.join(tmpdir, "redteam-report.html"))
            assert os.path.exists(os.path.join(tmpdir, "redteam-report.junit.xml"))

    def test_output_dir_created(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "nested", "reports")
            engine = ReportEngine(sample_report, output_dir=outdir)
            engine.generate_json()
            assert os.path.exists(outdir)
            assert os.path.exists(os.path.join(outdir, "redteam-report.json"))

    def test_failed_report_html(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            filepath = engine.generate_html()
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            assert "FAIL" in content
            assert "failed" in content

    def test_junit_has_failure_element(self, sample_report):
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReportEngine(sample_report, output_dir=tmpdir)
            filepath = engine.generate_junit()
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            assert "<failure" in content