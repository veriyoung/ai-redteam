"""
AI Red Team - YAML 探测加载器
支持从预设目录和自定义路径加载探测定制文件
"""
import os
import glob
import yaml
from typing import List, Optional
from ..models.types import Probe, VulnCategory, AttackVector, Severity

# 预设目录路径（相对于 probes/ 目录）
_PRESETS_DIR = os.path.dirname(os.path.abspath(__file__))

PRESET_GROUPS = {
    "owasp": os.path.join(_PRESETS_DIR, "presets", "owasp"),
    "unconventional": os.path.join(_PRESETS_DIR, "presets", "unconventional"),
    "zh_cn": os.path.join(_PRESETS_DIR, "presets", "zh_cn"),
    "all_unconventional": os.path.join(_PRESETS_DIR, "presets", "unconventional"),
}

PRESET_ALIASES = {
    "all": ["owasp", "unconventional", "zh_cn"],
    "full": ["owasp", "unconventional", "zh_cn"],
    "unconventional": ["unconventional"],
}

DEFAULT_PRESETS = ["owasp", "unconventional", "zh_cn"]


def _parse_yaml_probes(filepath: str) -> List[Probe]:
    """从单个 YAML 文件解析 Probe 列表"""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not data or "probes" not in data:
        return []

    default_category = data.get("category", "prompt_injection")
    probes = []

    for item in data["probes"]:
        try:
            category = VulnCategory(item.get("category", default_category))
            vector = AttackVector(item.get("vector", "direct_injection"))
            severity = Severity(item.get("severity", "high"))

            rounds_raw = item.get("rounds") or []
            rounds = []
            for r in rounds_raw:
                rounds.append({
                    "role": str(r.get("role", "user")),
                    "content": str(r.get("content", "")),
                })

            probe = Probe(
                id=str(item.get("id", "unknown")),
                category=category,
                vector=vector,
                template=str(item.get("template", "{{PAYLOAD}}")),
                payload=str(item.get("payload", "")),
                severity=severity,
                description=str(item.get("description", "")),
                tags=list(item.get("tags", [])),
                metadata=item.get("metadata", {}),
                rounds=rounds,
            )
            probes.append(probe)
        except (ValueError, KeyError) as e:
            print(f"[WARN] Skipping probe in {filepath}: {e}")
            continue

    return probes


def _list_yaml_files(directory: str) -> List[str]:
    """列出目录下所有 .yaml/.yml 文件"""
    if not os.path.isdir(directory):
        return []
    files = glob.glob(os.path.join(directory, "*.yaml"))
    files += glob.glob(os.path.join(directory, "*.yml"))
    return sorted(files)


def _resolve_preset(name: str) -> List[str]:
    """解析预设名称为 YAML 文件路径列表"""
    # 如果是已知组名
    if name in PRESET_GROUPS:
        return _list_yaml_files(PRESET_GROUPS[name])

    # 如果是别名
    if name in PRESET_ALIASES:
        files = []
        for sub in PRESET_ALIASES[name]:
            files.extend(_resolve_preset(sub))
        return files

    # 尝试在预设目录中查找特定文件名
    for group_dir in PRESET_GROUPS.values():
        candidate = os.path.join(group_dir, f"{name}.yaml")
        if os.path.isfile(candidate):
            return [candidate]
        candidate_yml = os.path.join(group_dir, f"{name}.yml")
        if os.path.isfile(candidate_yml):
            return [candidate_yml]

    # 当作文件路径
    if os.path.isfile(name):
        return [name]

    return []


def load_preset_probes(presets: Optional[List[str]] = None) -> List[Probe]:
    """从预设目录加载探测

    Args:
        presets: 预设名称列表，如 ["owasp", "unconventional"]。
                 None 表示加载所有默认预设。
                 支持别名: "all"/"full" = 全部

    Returns:
        Probe 对象列表
    """
    if presets is None:
        presets = DEFAULT_PRESETS

    all_files = []
    for name in presets:
        resolved = _resolve_preset(name)
        all_files.extend(resolved)

    # 去重
    seen = set()
    unique_files = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    probes = []
    for filepath in unique_files:
        probes.extend(_parse_yaml_probes(filepath))

    return probes


def load_custom_probes(filepath: str) -> List[Probe]:
    """从 JSON 或 YAML 文件加载自定义探测（兼容旧接口）"""
    if not os.path.exists(filepath):
        return []

    if filepath.endswith(('.yaml', '.yml')):
        return _parse_yaml_probes(filepath)

    # 兼容旧的 JSON 格式
    import json
    from ..models.types import Probe, VulnCategory, AttackVector, Severity

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    probes = []
    for item in data:
        probe = Probe(
            id=item.get("id", "custom-unknown"),
            category=VulnCategory(item.get("category", "prompt_injection")),
            vector=AttackVector(item.get("vector", "direct_injection")),
            template=item.get("template", "{{PAYLOAD}}"),
            payload=item.get("payload", ""),
            severity=Severity(item.get("severity", "high")),
            description=item.get("description", ""),
            tags=item.get("tags", []),
        )
        probes.append(probe)
    return probes


def load_custom_dir(directory: str) -> List[Probe]:
    """从目录加载所有 YAML/JSON 自定义探测"""
    if not os.path.isdir(directory):
        return []

    probes = []
    for f in sorted(os.listdir(directory)):
        filepath = os.path.join(directory, f)
        if f.endswith(('.yaml', '.yml', '.json')):
            probes.extend(load_custom_probes(filepath))
    return probes
