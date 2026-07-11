"""
AI Red Team - 攻击探测库
从 YAML 预设文件加载内置攻击模板，按 OWASP LLM Top 10 分类。
兼容旧的硬编码 Probe 变量名（延迟加载）。
"""
import json
import os
from typing import List

from ..models.types import Probe, VulnCategory, AttackVector, Severity
from .loader import (
    load_preset_probes,
    load_custom_probes as _load_custom_probes,
    load_custom_dir,
    DEFAULT_PRESETS,
)

# 类别到 YAML 预设文件名的映射
_CATEGORY_PRESET_MAP = {
    VulnCategory.PROMPT_INJECTION: "llm01_prompt_injection",
    VulnCategory.SYSTEM_PROMPT_LEAK: "llm07_system_prompt_leak",
    VulnCategory.PII_LEAK: "llm02_pii_leak",
    VulnCategory.JAILBREAK: "llm01_jailbreak",
    VulnCategory.HARMFUL_CONTENT: "llm06_harmful_content",
    VulnCategory.EXCESSIVE_AGENCY: "llm08_excessive_agency",
    VulnCategory.RAG_POISON: "llm08_rag_poison",
}

# 缓存已加载的探测
_cache = {}


def _get_cached(category_name):
    """按类别名获取缓存的探测列表"""
    if category_name not in _cache:
        _cache[category_name] = load_preset_probes([category_name])
    return _cache[category_name]


# 向后兼容的模块级变量（延迟加载）
def _lazy_probes(category_name):
    """创建惰性加载的属性描述符"""
    class LazyProbes:
        def __init__(self, name):
            self._name = name

        def __iter__(self):
            return iter(_get_cached(self._name))

        def __getitem__(self, index):
            return _get_cached(self._name)[index]

        def __len__(self):
            return len(_get_cached(self._name))

        def __add__(self, other):
            return list(_get_cached(self._name)) + list(other)

        def __radd__(self, other):
            return list(other) + list(_get_cached(self._name))

        def __repr__(self):
            return repr(list(_get_cached(self._name)))

    return LazyProbes(category_name)


# 展平后的完整探测列表（惰性加载，兼容旧代码直接访问列表）
PROMPT_INJECTION_PROBES = _lazy_probes("owasp")
SYSTEM_PROMPT_LEAK_PROBES = _lazy_probes("owasp")
PII_LEAK_PROBES = _lazy_probes("owasp")
JAILBREAK_PROBES = _lazy_probes("owasp")
HARMFUL_CONTENT_PROBES = _lazy_probes("owasp")
EXCESSIVE_AGENCY_PROBES = _lazy_probes("owasp")
RAG_POISON_PROBES = _lazy_probes("owasp")
ZH_CN_SPECIFIC_PROBES = _lazy_probes("zh_cn")


def get_all_probes() -> List[Probe]:
    """获取所有内置探测用例（从所有默认预设加载）"""
    return load_preset_probes(DEFAULT_PRESETS)


def get_probes_by_category(category: VulnCategory) -> List[Probe]:
    """按漏洞类别获取探测用例"""
    all_probes = get_all_probes()
    return [p for p in all_probes if p.category == category]


def load_custom_probes(filepath: str) -> List[Probe]:
    """从 JSON 或 YAML 文件加载自定义探测（兼容旧接口）"""
    return _load_custom_probes(filepath)
