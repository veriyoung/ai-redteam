"""
AI Red Team - 报告引擎
支持 JSON / HTML / JUnit XML 输出格式
"""
import json
import os
from datetime import datetime
from typing import List

from ..models.types import TestRunReport, VulnCategory, Severity


class ReportEngine:
    """报告生成引擎"""

    def __init__(self, report: TestRunReport, output_dir: str = "."):
        self.report = report
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self, formats: List[str] = None):
        """生成所有格式的报告"""
        formats = formats or self.report.config.output_formats
        for fmt in formats:
            if fmt == "compliance":
                self.generate_compliance()
            else:
                getattr(self, f"generate_{fmt}")()

    def generate_compliance(self):
        """生成合规审计报告"""
        from .compliance import generate_compliance_report, generate_compliance_summary_text

        results_by_category = {}
        for cat_val, cat_report in self.report.category_reports.items():
            results_by_category[cat_val] = cat_report.results

        filepath = generate_compliance_report(results_by_category, self.output_dir)
        compliance_data = {}
        with open(filepath, "r", encoding="utf-8") as f:
            import json
            compliance_data = json.load(f)
        summary = generate_compliance_summary_text(compliance_data)
        with open(os.path.join(self.output_dir, "redteam-compliance-summary.txt"), "w", encoding="utf-8") as f:
            f.write(summary)
        return filepath

    def generate_json(self):
        """生成JSON报告"""
        data = {
            "name": self.report.config.name,
            "target_model": self.report.target_model,
            "timestamp": self.report.start_time,
            "duration_seconds": self.report.duration_seconds,
            "summary": {
                "total_probes": self.report.total_probes,
                "passed": self.report.total_passed,
                "failed": self.report.total_failed,
                "errors": self.report.total_errors,
                "overall_asr": self.report.overall_asr,
                "overall_safety_score": self.report.overall_safety_score,
                "passed_threshold": self.report.passed_threshold,
            },
            "categories": {},
            "results": [],
        }
        for cat_val, cat_report in self.report.category_reports.items():
            data["categories"][cat_val] = {
                "total": cat_report.total,
                "passed": cat_report.passed,
                "failed": cat_report.failed,
                "errors": cat_report.errors,
                "asr": cat_report.asr,
                "safety_score": cat_report.safety_score,
                "min_threshold": cat_report.min_threshold,
                "passed_threshold": cat_report.passed_threshold,
                "severity": cat_report.severity.value,
            }
            for r in cat_report.results:
                data["results"].append({
                    "probe_id": r.probe.id,
                    "category": r.probe.category.value,
                    "vector": r.probe.vector.value,
                    "description": r.probe.description,
                    "prompt": r.probe.render()[:200],
                    "response": r.response[:300] if r.response else "",
                    "passed": r.passed,
                    "score": r.score,
                    "severity": r.severity.value,
                    "judge_reasoning": r.judge_reasoning,
                    "latency_ms": r.latency_ms,
                    "error": r.error,
                })

        filepath = os.path.join(self.output_dir, "redteam-report.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return filepath

    def generate_html(self):
        """生成HTML报告"""
        r = self.report
        status_class = "passed" if r.passed_threshold else "failed"
        status_text = "PASS" if r.passed_threshold else "FAIL"

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Red Team - {r.config.name}</title>
<style>
:root {{ --bg:#f8f9fb; --surface:#fff; --ink:#1a1d23; --muted:#6b7280; --rule:#e5e7eb; --pass:#059669; --fail:#dc2626; --warn:#d97706; }}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; font-size:14px; line-height:1.6; color:var(--ink); background:var(--bg); }}
.container {{ max-width:960px; margin:0 auto; padding:2rem; }}
h1 {{ font-size:1.8rem; margin-bottom:.5rem; }}
.meta {{ color:var(--muted); margin-bottom:2rem; font-size:.85rem; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
.stat {{ background:var(--surface); border:1px solid var(--rule); border-radius:8px; padding:1rem; text-align:center; }}
.stat .num {{ font-size:1.8rem; font-weight:700; }}
.stat .label {{ font-size:.8rem; color:var(--muted); }}
.stat.pass .num {{ color:var(--pass); }}
.stat.fail .num {{ color:var(--fail); }}
.badge {{ display:inline-block; padding:.25rem .75rem; border-radius:4px; font-weight:700; font-size:.9rem; }}
.badge.pass {{ background:#ecfdf5; color:var(--pass); }}
.badge.fail {{ background:#fef2f2; color:var(--fail); }}
table {{ width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--rule); margin:1.5rem 0; font-size:.85rem; }}
th {{ background:var(--ink); color:#fff; padding:.6rem .8rem; text-align:left; font-size:.8rem; }}
td {{ padding:.5rem .8rem; border-bottom:1px solid var(--rule); vertical-align:top; }}
tr:last-child td {{ border-bottom:none; }}
tr:hover {{ background:rgba(0,0,0,.02); }}
.sev-critical {{ color:var(--fail); font-weight:700; }}
.sev-high {{ color:var(--warn); font-weight:700; }}
.sev-medium {{ color:var(--muted); }}
.pass-mark {{ color:var(--pass); font-weight:700; }}
.fail-mark {{ color:var(--fail); font-weight:700; }}
.response {{ max-height:80px; overflow-y:auto; font-size:.8rem; color:var(--muted); white-space:pre-wrap; }}
footer {{ margin-top:2rem; padding-top:1rem; border-top:1px solid var(--rule); font-size:.8rem; color:var(--muted); }}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ AI Red Team Report</h1>
<p class="meta">{r.config.name} | 目标模型: {r.target_model} | {r.start_time}</p>
<div class="stats">
  <div class="stat"><div class="num">{r.total_probes}</div><div class="label">总探测数</div></div>
  <div class="stat pass"><div class="num">{r.total_passed}</div><div class="label">通过</div></div>
  <div class="stat fail"><div class="num">{r.total_failed}</div><div class="label">未通过</div></div>
  <div class="stat fail"><div class="num">{r.total_errors}</div><div class="label">错误</div></div>
  <div class="stat"><div class="num">{r.overall_safety_score:.1%}</div><div class="label">安全评分</div></div>
  <div class="stat"><div class="num">{r.overall_asr:.1%}</div><div class="label">攻击成功率</div></div>
</div>
<p>总体结果: <span class="badge {status_class}">{status_text}</span> (阈值: {r.config.overall_threshold:.0%})</p>
<h2 style="margin-top:2rem">分类详情</h2>
<table>
<thead><tr><th>漏洞类别</th><th>总数</th><th>通过</th><th>未通过</th><th>ASR</th><th>安全评分</th><th>阈值</th><th>状态</th></tr></thead>
<tbody>"""

        for cat_val, cat in r.category_reports.items():
            cat_status = "pass" if cat.passed_threshold else "fail"
            cat_label = "通过" if cat.passed_threshold else "未达标"
            html += f"""<tr>
<td>{cat_val}</td><td>{cat.total}</td><td>{cat.passed}</td><td>{cat.failed}</td>
<td>{cat.asr:.1%}</td><td>{cat.safety_score:.1%}</td><td>{cat.min_threshold:.0%}</td>
<td><span class="badge {cat_status}">{cat_label}</span></td></tr>"""

        html += """</tbody></table>
<h2 style="margin-top:2rem">探测明细</h2>
<table>
<thead><tr><th>ID</th><th>类别</th><th>描述</th><th>严重性</th><th>通过</th><th>评分</th><th>判定理由</th><th>响应</th><th>延迟</th></tr></thead>
<tbody>"""

        for cat_report in r.category_reports.values():
            for res in cat_report.results:
                sev_class = f"sev-{res.severity.value}"
                pass_class = "pass-mark" if res.passed else "fail-mark"
                pass_text = "✓" if res.passed else "✗"
                response_text = res.response[:200].replace("<", "&lt;").replace(">", "&gt;") if res.response else (res.error or "")
                html += f"""<tr>
<td>{res.probe.id}</td><td>{res.probe.category.value}</td><td>{res.probe.description}</td>
<td><span class="{sev_class}">{res.severity.value}</span></td>
<td><span class="{pass_class}">{pass_text}</span></td>
<td>{res.score:.1f}</td><td>{res.judge_reasoning}</td>
<td class="response">{response_text}</td><td>{res.latency_ms:.0f}ms</td></tr>"""

        html += f"""</tbody></table>
<footer>AI Red Team PoC | 生成时间: {datetime.now().isoformat()}</footer>
</div></body></html>"""

        filepath = os.path.join(self.output_dir, "redteam-report.html")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return filepath

    def generate_junit(self):
        """生成JUnit XML报告（CI/CD集成）"""
        r = self.report
        total = r.total_probes
        failures = r.total_failed
        errors = r.total_errors

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="AI Red Team - {r.config.name}" tests="{total}" failures="{failures}" errors="{errors}" time="{r.duration_seconds:.2f}">',
        ]

        for cat_report in r.category_reports.values():
            for res in cat_report.results:
                if res.error:
                    xml_lines.append(f'<testcase name="{res.probe.id}: {res.probe.description}" classname="ai_redteam" time="{res.latency_ms/1000:.3f}">')
                    xml_lines.append(f'<error message="{res.error}" type="ERROR">{res.error}</error>')
                    xml_lines.append('</testcase>')
                elif not res.passed:
                    xml_lines.append(f'<testcase name="{res.probe.id}: {res.probe.description}" classname="ai_redteam" time="{res.latency_ms/1000:.3f}">')
                    xml_lines.append(f'<failure message="{res.judge_reasoning}" type="SECURITY_VIOLATION">')
                    escaped_resp = res.response[:500].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if res.response else ""
                    xml_lines.append(f'Probe: {res.probe.render()[:300]}')
                    xml_lines.append(f'Response: {escaped_resp}')
                    xml_lines.append(f'Score: {res.score}')
                    xml_lines.append('</failure>')
                    xml_lines.append('</testcase>')
                else:
                    xml_lines.append(f'<testcase name="{res.probe.id}: {res.probe.description}" classname="ai_redteam" time="{res.latency_ms/1000:.3f}"/>')

        xml_lines.append('</testsuite>')

        filepath = os.path.join(self.output_dir, "redteam-report.junit.xml")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(xml_lines))
        return filepath
