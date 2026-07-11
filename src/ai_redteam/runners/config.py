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


def load_config(filepath: str) -> TestRunConfig:
    """从YAML文件加载配置"""
    if not os.path.exists(filepath):
        return TestRunConfig()

    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # 合并默认配置
    config = {**DEFAULT_CONFIG, **data}

    target = config.get("target", {})
    categories_raw = config.get("categories", [])
    categories = [VulnCategory(c) for c in categories_raw if isinstance(c, str)]

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
    categories = [VulnCategory(c) for c in categories_raw if isinstance(c, str)]

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
