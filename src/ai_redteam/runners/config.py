"""
AI Red Team - 配置加载器
支持YAML配置文件
"""
import os
import yaml
from typing import List, Optional
from ..models.types import TestRunConfig, VulnCategory


DEFAULT_CONFIG = {
    "name": "AI Red Team Test",
    "target": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key": "",
        "base_url": "",
        "system_prompt": "",
        "timeout": 30.0,
    },
    "categories": [
        "prompt_injection", "system_prompt_leak", "pii_leak",
        "jailbreak", "harmful_content", "excessive_agency",
        "rag_poison", "tool_hijack",
    ],
    "presets": ["owasp", "unconventional", "zh_cn"],
    "max_concurrent": 5,
    "timeout_per_probe": 30.0,
    "overall_threshold": 0.80,
    "output_formats": ["json", "html"],
    "output_dir": "./redteam-results",
    "custom_probes": [],
    "custom_probes_dir": "",
    "mutate": True,
    "mutations_per_probe": 2,
}


def _parse_categories(categories_raw: list, source: str = "") -> List[VulnCategory]:
    """安全解析漏洞类别列表，无效值给出友好提示并跳过"""
    valid_categories = [c.value for c in VulnCategory]
    parsed = []
    invalid = []
    for c in categories_raw:
        if not isinstance(c, str):
            continue
        try:
            parsed.append(VulnCategory(c))
        except ValueError:
            invalid.append(c)

    if invalid:
        label = f" ({source})" if source else ""
        print(f" 警告: 以下类别无效，已自动跳过{label}: {', '.join(invalid)}")
        print(f"   有效类别: {', '.join(valid_categories)}")

    if not parsed:
        print(f" 没有有效类别，将使用默认类别。")
        return [VulnCategory(c) for c in DEFAULT_CONFIG["categories"]]

    return parsed


def load_config(filepath: str) -> TestRunConfig:
    """从YAML文件加载配置"""
    if not os.path.exists(filepath):
        print(f" 配置文件不存在: {filepath}，使用默认配置。")
        return TestRunConfig()

    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # 合并默认配置
    config = {**DEFAULT_CONFIG, **data}

    target = config.get("target", {})

    # 如果配置文件中 provider 为空或未设置，尝试从 --mock 推断
    if not target.get("provider") or target.get("provider") == "openai":
        api_key = target.get("api_key", "") or ""
        if not api_key and not os.environ.get("OPENAI_API_KEY"):
            print(" 未检测到 API 密钥，将自动切换到 Mock 模式。")
            print("   设置 OPENAI_API_KEY 环境变量或修改配置文件中的 api_key 以使用真实模型。")
            target["provider"] = "mock"
            target["model"] = "mock"

    categories_raw = config.get("categories", [])
    categories = _parse_categories(categories_raw, source=filepath)

    tc = TestRunConfig(
        name=config.get("name", "AI Red Team Test"),
        target=target,
        categories=categories,
        max_concurrent=config.get("max_concurrent", 5),
        timeout_per_probe=config.get("timeout_per_probe", 30.0),
        overall_threshold=config.get("overall_threshold", 0.80),
        output_formats=config.get("output_formats", ["json", "html"]),
    )

    # 附加属性（非 dataclass 字段，通过 setattr 注入）
    tc.presets = config.get("presets", ["owasp", "unconventional", "zh_cn"])
    tc.custom_probes = config.get("custom_probes", [])
    tc.custom_probes_dir = config.get("custom_probes_dir", "")
    tc.mutations_per_probe = config.get("mutations_per_probe", 2)
    return tc


def load_config_dict(data: dict) -> TestRunConfig:
    """从字典加载配置（用于CLI参数）"""
    config = {**DEFAULT_CONFIG, **data}

    target = config.get("target", {})
    categories_raw = config.get("categories", [])
    categories = _parse_categories(categories_raw, source="命令行参数")

    tc = TestRunConfig(
        name=config.get("name", "AI Red Team Test"),
        target=target,
        categories=categories,
        max_concurrent=config.get("max_concurrent", 5),
        timeout_per_probe=config.get("timeout_per_probe", 30.0),
        overall_threshold=config.get("overall_threshold", 0.80),
        output_formats=config.get("output_formats", ["json", "html"]),
    )
    tc.presets = config.get("presets", ["owasp", "unconventional", "zh_cn"])
    tc.custom_probes = config.get("custom_probes", [])
    tc.custom_probes_dir = config.get("custom_probes_dir", "")
    tc.mutations_per_probe = config.get("mutations_per_probe", 2)
    return tc