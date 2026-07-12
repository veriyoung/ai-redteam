"""
真实模型跑 E2E 测试 — 使用 Pollinations 免费 API（无需 Key）
每个攻击向量取1条探测，并发执行并打印结果
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_redteam.models.types import TestRunConfig, VulnCategory, AttackVector
from ai_redteam.models.adapter import create_adapter
from ai_redteam.probes.loader import load_preset_probes
from ai_redteam.probes.library import get_probes_by_category
from ai_redteam.runners.tester import TestRunner
from ai_redteam.mutators.engine import Mutator


async def run_sample(probe, runner):
    result = await runner.run_single(probe)
    vector_label = probe.vector.value if hasattr(probe.vector, 'value') else str(probe.vector)
    cat_label = probe.category.value if hasattr(probe.category, 'value') else str(probe.category)
    status = "PASS" if result.passed else "FAIL"
    response_snippet = (result.response or "")[:120].replace("\n", "\\n")
    print(f"  [{status}] {probe.id:20s} | {cat_label:18s} | {vector_label:22s} | {result.latency_ms:7.1f}ms | {response_snippet}")
    return result


async def main():
    provider = sys.argv[1] if len(sys.argv) > 1 else "pollinations"
    model = sys.argv[2] if len(sys.argv) > 2 else "openai-fast"

    print(f"=" * 90)
    print(f"  AI Red Team E2E — 真实模型 ({provider}/{model})")
    print(f"=" * 90)

    # 1. 加载探测
    print("\n--- 加载探测 ---")
    presets = load_preset_probes(["owasp", "unconventional", "zh_cn"])
    print(f"  预设加载: {len(presets)} 条")

    tool_hijack_probes = get_probes_by_category(VulnCategory.TOOL_HIJACK)
    print(f"  TOOL_HIJACK: {len(tool_hijack_probes)} 条")

    # 2. 每个向量取1条代表
    print("\n--- 选取代表探测（每向量1条 + 多轮1条 + 中文1条）---")
    seen = set()
    samples = []
    for p in presets:
        key = p.vector
        if key not in seen:
            seen.add(key)
            samples.append(p)

    print(f"  选取: {len(samples)} 条探测, 覆盖 {len(seen)} 种向量")

    # 也加一条变异后的
    if samples:
        mutated = Mutator.mutate(samples[0])
        if mutated:
            samples.append(mutated)
            print(f"  +1 变异探测: {mutated.id}")

    print(f"  总计: {len(samples)} 条探测")

    # 3. 配置运行器
    print("\n--- 初始化运行器 ---")
    target = {"provider": provider, "model": model}
    config = TestRunConfig(
        name=f"E2E真实模型-{provider}",
        target=target,
        categories=[],
        max_concurrent=3,
        timeout_per_probe=30.0,
    )
    runner = TestRunner(config)
    runner.setup()
    print(f"  适配器: {type(runner.adapter).__name__}")

    # 4. 并发执行
    print(f"\n--- 开始执行 {len(samples)} 条探测 ---\n")
    tasks = [run_sample(p, runner) for p in samples]
    results = await asyncio.gather(*tasks)

    # 5. 汇总
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    errors = sum(1 for r in results if r.error)
    avg_latency = sum(r.latency_ms for r in results) / max(total, 1)

    report = runner.build_report()

    print(f"\n--- 结果汇总 ---")
    print(f"  总数: {total},  通过(安全): {passed},  失败(漏洞): {failed},  错误: {errors}")
    print(f"  平均延迟: {avg_latency:.0f}ms")
    print(f"  安全评分: {report.overall_safety_score:.2%}")
    print(f"  ASR:       {report.overall_asr:.2%}")

    # 6. 按类别分报告
    print(f"\n--- 类别报告 ---")
    for cat_name, cr in report.category_reports.items():
        print(f"  {cat_name:20s}: 安全={cr.safety_score:.2%}  ASR={cr.asr:.2%}  ({cr.passed}/{cr.total}通过)")

    # 7. 按向量分
    print(f"\n--- 向量结果 ---")
    vector_results = {}
    for r in results:
        v = r.probe.vector.value if hasattr(r.probe.vector, 'value') else str(r.probe.vector)
        vector_results.setdefault(v, []).append(r)
    for v, rs in sorted(vector_results.items()):
        p = sum(1 for r in rs if r.passed)
        t = len(rs)
        print(f"  {v:25s}: {p}/{t} 通过  ({p/t:.0%})")


if __name__ == "__main__":
    asyncio.run(main())
