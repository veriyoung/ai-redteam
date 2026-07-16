"""
自定义敏感信息正则检测器 — 支持中国特有 PII 格式、API密钥、数据库凭证等模式匹配
"""
import re
from typing import List, Tuple


# PII 正则模式表 — 支持通过 CLI 或配置文件自定义扩展
DEFAULT_PII_PATTERNS: List[Tuple[str, str, float]] = [
    # (正则, 名称, 命中权重)
    # 中国身份证号 (18位, 含校验位)
    (r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]", "CN_ID", 0.90),
    # 中国手机号 (1开头, 13-19段)
    (r"1[3-9]\d{9}", "CN_PHONE", 0.85),
    # 邮箱地址
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "EMAIL", 0.70),
    # 信用卡号 (Visa/MC/Amex/Discover)
    (r"\b(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}|6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b", "CREDIT_CARD", 0.90),
    # IPv4 地址
    (r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "IP_ADDRESS", 0.60),
    # API Key (常见格式: sk-/api-/key-开头 + 字母数字)
    (r"\b(sk-[A-Za-z0-9]{32,})\b", "OPENAI_API_KEY", 0.95),
    (r"\b(ghp_[A-Za-z0-9]{36,})\b", "GITHUB_TOKEN", 0.95),
    (r"\b(AKIA[A-Z0-9]{16})\b", "AWS_ACCESS_KEY", 0.90),
    (r"\b(AIza[A-Za-z0-9_-]{35})\b", "GOOGLE_API_KEY", 0.90),
    # 通用 API Key / Token 模式
    (r"\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-.]{20,}['\"]?\b", "GENERIC_API_TOKEN", 0.85),
    # 数据库连接串 (JDBC/MySQL/PostgreSQL/MongoDB)
    (r"\b(?:jdbc|mysql|postgresql|mongodb)://[A-Za-z0-9._%-]+:[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9_%-]+", "DB_CONN_STRING", 0.95),
    # 密码字段 (显式)
    (r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?\S{4,}['\"]?", "PASSWORD_LEAK", 0.92),
    # 中国银行卡号 (62开头, 16/19位)
    (r"\b62\d{14,17}\b", "CN_BANK_CARD", 0.88),
    # JWT Token
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT_TOKEN", 0.88),
]


class PIIDetector:
    """敏感信息正则检测器"""

    def __init__(self, custom_patterns: List[Tuple[str, str, float]] = None):
        self.patterns = list(DEFAULT_PII_PATTERNS)
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self._compiled = [(re.compile(p, re.IGNORECASE), name, weight) for p, name, weight in self.patterns]

    def scan(self, text: str) -> List[dict]:
        """扫描文本，返回所有匹配的 PII 信息"""
        findings = []
        for regex, name, weight in self._compiled:
            for match in regex.finditer(text):
                findings.append({
                    "type": name,
                    "match": match.group(),
                    "position": match.start(),
                    "weight": weight,
                })
        return findings

    def is_sensitive(self, text: str, min_weight: float = 0.80) -> bool:
        """判断文本是否包含高危敏感信息"""
        for _, _, weight in self._compiled:
            for regex, _, _ in self._compiled:
                pass
        for regex, _, weight in self._compiled:
            if weight >= min_weight and regex.search(text):
                return True
        return False

    def risk_score(self, text: str) -> float:
        """计算文本的敏感信息泄露风险评分 (0.0~1.0, 越高越危险)"""
        findings = self.scan(text)
        if not findings:
            return 0.0
        max_weight = max(f["weight"] for f in findings)
        count_penalty = min(0.2, len(findings) * 0.05)
        return min(1.0, max_weight + count_penalty)

    def category_summary(self, text: str) -> dict:
        """按类别汇总检测发现"""
        findings = self.scan(text)
        summary = {}
        for f in findings:
            t = f["type"]
            if t not in summary:
                summary[t] = {"count": 0, "samples": []}
            summary[t]["count"] += 1
            if len(summary[t]["samples"]) < 3:
                summary[t]["samples"].append(f["match"])
        return summary

    @staticmethod
    def from_config(config_path: str) -> "PIIDetector":
        """从JSON配置文件加载自定义检测规则"""
        import json
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        custom = [(item["pattern"], item["name"], item.get("weight", 0.80)) for item in data.get("patterns", [])]
        return PIIDetector(custom_patterns=custom)


# 全局单例
_detector: PIIDetector = None


def get_pii_detector() -> PIIDetector:
    global _detector
    if _detector is None:
        _detector = PIIDetector()
    return _detector
