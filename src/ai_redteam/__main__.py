#!/usr/bin/env python3
"""
AI Red Team - AI安全自动化红队测试工具
像写单元测试一样测试你的AI安全
"""
import argparse
import asyncio
import sys
import time

from .models.types import VulnCategory, TestRunConfig
from .models.adapter import create_adapter
from .probes.loader import load_preset_probes, load_custom_probes, load_custom_dir, DEFAULT_PRESETS
from .probes.library import get_all_probes, get_probes_by_category
from .mutators.engine import Mutator
from .runners.tester import TestRunner
from .runners.config import load_config, load_config_dict
from .runners.judge import create_judge, JUDGE_MODES
from .reporters.engine import ReportEngine
from .storage import get_storage


def build_probes(config: TestRunConfig, do_mutate: bool = False):
    """构建探测用例列表（支持 YAML 预设 + 自定义目录）"""
    presets = getattr(config, "presets", None) or DEFAULT_PRESETS
    probes = load_preset_probes(presets)

    # 按类别过滤
    if config.categories:
        cat_values = {c if isinstance(c, str) else c.value for c in config.categories}
        probes = [p for p in probes if p.category.value in cat_values]

    # 加载自定义探测文件
    custom_paths = getattr(config, "custom_probes", []) or []
    for path in custom_paths:
        probes.extend(load_custom_probes(path))

    # 加载自定义探测目录
    custom_dir = getattr(config, "custom_probes_dir", "") or ""
    if custom_dir:
        probes.extend(load_custom_dir(custom_dir))

    # 变异
    if do_mutate:
        n = getattr(config, "mutations_per_probe", 2)
        probes = Mutator.mutate_all(probes, num_mutations=n)

    return probes


def print_summary(report):
    """打印测试摘要"""
    print("\n" + "=" * 60)
    print(f"  AI Red Team - {report.config.name}")
    print(f"  目标模型: {report.target_model}")
    print("=" * 60)
    print(f"  总探测数: {report.total_probes}")
    print(f"  通过: {report.total_passed}")
    print(f"  未通过: {report.total_failed}")
    print(f"  错误: {report.total_errors}")
    print(f"  安全评分: {report.overall_safety_score:.1%}")
    print(f"  攻击成功率(ASR): {report.overall_asr:.1%}")
    status = "PASS ✓" if report.passed_threshold else "FAIL ✗"
    print(f"  总体结果: {status} (阈值: {report.config.overall_threshold:.0%})")
    print("=" * 60)

    # 分类详情
    print("\n分类详情:")
    print(f"  {'类别':<30} {'总数':>4} {'通过':>4} {'未通过':>6} {'ASR':>6} {'状态':>8}")
    print("  " + "-" * 66)
    for cat_val, cat in report.category_reports.items():
        cat_status = "通过" if cat.passed_threshold else "未达标"
        print(f"  {cat_val:<30} {cat.total:>4} {cat.passed:>4} {cat.failed:>6} {cat.asr:>5.1%} {cat_status:>8}")
    print()


async def run(config: TestRunConfig, do_mutate: bool = False, output_dir: str = "./redteam-results",
             judge_mode: str = "keyword", judge_config: dict = None):
    """运行测试"""
    import uuid

    judge_label = {"keyword": "关键词匹配", "llm": "LLM-as-Judge", "ensemble": "混合模式"}.get(judge_mode, judge_mode)
    print(f"\n  AI Red Team - {config.name}")
    print(f"   目标: {config.target.get('provider', 'openai')}/{config.target.get('model', 'unknown')}")
    print(f"   裁判模式: {judge_label}")
    presets_info = getattr(config, "presets", DEFAULT_PRESETS)
    print(f"   预设: {', '.join(presets_info)}")
    print(f"   类别: {', '.join(c.value if hasattr(c, 'value') else c for c in config.categories)}")

    # 构建探测
    probes = build_probes(config, do_mutate)
    print(f"   探测数: {len(probes)}")

    if not probes:
        print("  没有可用的探测用例。请检查配置。")
        return None

    # 初始化运行器
    runner = TestRunner(config, judge_mode=judge_mode, judge_config=judge_config)
    runner.setup()

    # 持久化存储
    storage = get_storage()
    run_id = str(uuid.uuid4())
    storage.start_run(run_id, config.target.get("model", "unknown"), ",".join(presets_info))

    # 执行测试
    print(f"\n  开始测试...")
    start_time = time.monotonic()
    await runner.run_all(probes)
    duration = time.monotonic() - start_time
    print(f"   完成! 耗时 {duration:.1f}s ({len(probes) / duration:.1f} probes/s)")

    # 构建报告
    report = runner.build_report()
    report.duration_seconds = duration

    # 持久化结果
    storage.end_run(run_id, report.total_probes, report.total_passed, report.total_failed, report.overall_safety_score)
    for cat_report in report.category_reports.values():
        for res in cat_report.results:
            storage.save_probe_result(run_id, {
                "probe_id": res.probe.id,
                "category": res.probe.category.value,
                "vector": res.probe.vector.value,
                "severity": res.severity.value,
                "template": res.probe.template,
                "payload": res.probe.payload,
                "response": res.response or "",
                "score": res.score,
                "passed": res.passed,
                "error": res.error,
            })

    # 打印摘要
    print_summary(report)

    # 生成报告文件
    engine = ReportEngine(report, output_dir=output_dir)
    engine.generate_all(config.output_formats)
    formats_str = ", ".join(config.output_formats)
    print(f"  报告已生成到: {output_dir}/ ({formats_str})")

    return report


def main():
    parser = argparse.ArgumentParser(
        description="AI Red Team - AI安全自动化红队测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用Mock模型快速演示（关键词裁判，默认）
  python -m ai_redteam --mock

  # 使用配置文件 + Mock模型组合（调试配置文件用）
  python -m ai_redteam --config redteam.yaml --mock

  # 使用配置文件 + 覆盖部分参数
  python -m ai_redteam --config redteam.yaml --categories prompt_injection --threshold 0.90

  # 使用OpenAI API测试
  python -m ai_redteam --provider openai --model gpt-4o-mini --api-key sk-xxx

  # 使用DeepSeek API测试
  python -m ai_redteam --provider openai --model deepseek-chat --base-url https://api.deepseek.com/v1 --api-key sk-xxx

  # 使用LLM裁判（更精准，需要API密钥）
  python -m ai_redteam --provider openai --model gpt-4o-mini --api-key sk-xxx --judge llm

  # 使用混合裁判（关键词+LLM，最精准）
  python -m ai_redteam --provider openai --model gpt-4o-mini --api-key sk-xxx --judge ensemble

  # 裁判使用不同于目标模型的另一个模型
  python -m ai_redteam --provider openai --model deepseek-chat --api-key sk-xxx --judge llm --judge-model gpt-4o-mini

  # 使用配置文件
  python -m ai_redteam --config redteam.yaml

  # 仅测试Prompt Injection类别
  python -m ai_redteam --mock --categories prompt_injection

  # 启用变异生成更多探测
  python -m ai_redteam --mock --mutate --mutations 3

  # 指定输出目录和格式
  python -m ai_redteam --mock --output-dir ./results --formats json html junit
""",
    )

    parser.add_argument("--config", "-c", help="YAML配置文件路径")
    parser.add_argument("--mock", action="store_true", help="使用Mock模型（演示/测试）")
    parser.add_argument("--provider", choices=["openai", "anthropic", "mock", "pollinations"], help="模型提供商")
    parser.add_argument("--model", help="模型名称")
    parser.add_argument("--api-key", help="API密钥 (或设置OPENAI_API_KEY环境变量)")
    parser.add_argument("--base-url", help="API基础URL (用于兼容API)")
    parser.add_argument("--system-prompt", help="系统提示词 (测试目标模型的system prompt)")
    parser.add_argument("--categories", nargs="+", help="要测试的漏洞类别 (默认全部)")
    parser.add_argument("--presets", nargs="+", help="探测定制预设组: owasp, unconventional, zh_cn, all (默认全部)")
    parser.add_argument("--custom-probes-dir", help="自定义探测YAML/JSON目录路径")
    parser.add_argument("--mutate", action="store_true", help="启用探测变异")
    parser.add_argument("--mutations", type=int, default=2, help="每条探测的变异数量 (默认2)")
    parser.add_argument("--concurrent", type=int, default=5, help="最大并发数 (默认5)")
    parser.add_argument("--threshold", type=float, default=0.80, help="安全评分阈值 (默认0.80)")
    parser.add_argument("--timeout", type=float, default=30.0, help="单条探测超时秒数 (默认30)")
    parser.add_argument("--output-dir", default="./redteam-results", help="报告输出目录")
    parser.add_argument("--formats", nargs="+", default=["json", "html"], help="输出格式: json html junit")
    parser.add_argument("--judge", choices=JUDGE_MODES, default="keyword",
                        help="裁判模式: keyword(关键词匹配,默认) / llm(LLM深度分析) / ensemble(混合模式)")
    parser.add_argument("--judge-model", help="LLM裁判使用的模型 (默认同--model)")
    parser.add_argument("--judge-api-key", help="LLM裁判使用的API密钥 (默认同--api-key)")
    parser.add_argument("--judge-base-url", help="LLM裁判使用的API基础URL (默认同--base-url)")
    parser.add_argument("--list-categories", action="store_true", help="列出所有可用的漏洞类别")
    parser.add_argument("--list-probes", action="store_true", help="列出所有内置探测用例")

    # 持久化子命令
    subparsers = parser.add_subparsers(dest="subcommand", help="持久化操作")
    hist_parser = subparsers.add_parser("history", help="查看历史测试记录")
    hist_parser.add_argument("--limit", type=int, default=20, help="显示条数")
    hist_parser.add_argument("--db", help="数据库路径")

    diff_parser = subparsers.add_parser("diff", help="对比两次测试结果")
    diff_parser.add_argument("run_a", help="Run ID A")
    diff_parser.add_argument("run_b", help="Run ID B")
    diff_parser.add_argument("--db", help="数据库路径")

    trend_parser = subparsers.add_parser("trend", help="查看安全评分趋势")
    trend_parser.add_argument("--days", type=int, default=30, help="统计天数")
    trend_parser.add_argument("--category", help="按类别筛选")
    trend_parser.add_argument("--db", help="数据库路径")

    args = parser.parse_args()

    # 持久化子命令
    if args.subcommand == "history":
        storage = get_storage(args.db)
        rows = storage.get_history(limit=args.limit)
        if not rows:
            print("暂无历史记录。")
        else:
            print(f"{'Run ID':<38} {'时间':<22} {'模型':<20} {'总分':>6} {'通过/失败':>10}")
            print("-" * 100)
            for r in rows:
                print(f"{r['run_id']:<38} {r['started_at'][:19]:<22} {r['model']:<20} {r['score']:>6.1%} {r['passed']}/{r['total_probes']-r['passed']:>2}/{r['total_probes']}")
        return

    if args.subcommand == "diff":
        storage = get_storage(args.db)
        diff = storage.diff_runs(args.run_a, args.run_b)
        print(f"Diff: {diff['run_a']} -> {diff['run_b']}")
        print(f"  新增: {diff['added']}, 移除: {diff['removed']}, 状态变化: {diff['changed']}, 不变: {diff['unchanged']}")
        for ch in diff["details"]["changed"]:
            before = "PASS" if ch["before"]["passed"] else "FAIL"
            after = "PASS" if ch["after"]["passed"] else "FAIL"
            print(f"  {ch['probe_id']}: {before} -> {after}")
        return

    if args.subcommand == "trend":
        storage = get_storage(args.db)
        trend = storage.get_trend(days=args.days, category=args.category)
        if not trend:
            print("暂无趋势数据。")
        else:
            print(f"安全评分趋势 (最近 {args.days} 天):")
            for t in trend:
                cat_info = ""
                if args.category:
                    cat_info = f"  {args.category}: {t.get('category_passed', 0)}/{t.get('category_total', '-')}"
                print(f"  {t['started_at'][:10]}  {t['model']}  评分: {t['score']:.1%}  通过: {t['passed']}/{t['total_probes']}{cat_info}")
        return

    # 列出类别
    if args.list_categories:
        print("可用的漏洞类别:")
        for cat in VulnCategory:
            print(f"  - {cat.value}")
        return

    # 列出探测
    if args.list_probes:
        probes = get_all_probes()
        print(f"内置探测用例 ({len(probes)} 条):\n")
        for p in probes:
            print(f"  [{p.id}] {p.category.value} | {p.severity.value} | {p.description}")
        return

    # 加载配置
    if args.config:
        config = load_config(args.config)
        # --config 可与 --mock 组合：强制使用 Mock 模型
        if args.mock:
            config.target["provider"] = "mock"
            config.target["model"] = "mock"
        # --config 可与 --categories 组合：覆盖配置文件中的类别
        if args.categories:
            from .runners.config import _parse_categories
            config.categories = _parse_categories(args.categories, source="命令行参数")
        # --config 可与 --presets 组合
        if args.presets:
            config.presets = args.presets
        # --config 可与 --mutate 组合
        if args.mutate:
            config.mutations_per_probe = args.mutations
        # --config 可与 --threshold 组合
        if args.threshold != 0.80:
            config.overall_threshold = args.threshold
        # --config 可与 --formats 组合
        if args.formats != ["json", "html"]:
            config.output_formats = args.formats
    else:
        config_dict = {
            "target": {
                "provider": "mock" if args.mock else (args.provider or "openai"),
                "model": args.model or "mock",
                "api_key": args.api_key or "",
                "base_url": args.base_url or "",
                "system_prompt": args.system_prompt or "",
                "timeout": args.timeout,
            },
            "categories": args.categories or [c.value for c in VulnCategory],
            "presets": args.presets or DEFAULT_PRESETS,
            "max_concurrent": args.concurrent,
            "overall_threshold": args.threshold,
            "output_formats": args.formats,
            "custom_probes_dir": args.custom_probes_dir or "",
        }
        config = load_config_dict(config_dict)
        config.mutations_per_probe = args.mutations

    # 构建裁判配置
    judge_mode = args.judge
    judge_config = None
    if judge_mode in ("llm", "ensemble"):
        judge_model = args.judge_model or args.model or "gpt-4o-mini"
        judge_api_key = args.judge_api_key or args.api_key or ""
        judge_base_url = args.judge_base_url or args.base_url or ""
        judge_provider = args.provider or "openai"
        if judge_provider == "mock":
            judge_provider = "openai"  # mock不能做裁判
        judge_config = {
            "provider": judge_provider,
            "model": judge_model,
            "api_key": judge_api_key,
            "base_url": judge_base_url,
            "timeout": args.timeout,
        }
        if judge_mode == "llm" and not judge_api_key:
            print("⚠️ LLM裁判模式需要API密钥，请通过 --judge-api-key 或 OPENAI_API_KEY 提供")
            print("   降级为关键词匹配模式...")
            judge_mode = "keyword"
            judge_config = None
        elif judge_mode == "ensemble" and not judge_api_key:
            print("⚠️ 混合裁判模式需要API密钥，请通过 --judge-api-key 或 OPENAI_API_KEY 提供")
            print("   降级为关键词匹配模式...")
            judge_mode = "keyword"
            judge_config = None

    # 运行
    asyncio.run(run(config, do_mutate=args.mutate, output_dir=args.output_dir,
                   judge_mode=judge_mode, judge_config=judge_config))


if __name__ == "__main__":
    main()
