"""
合规审计报告 — 将对标 NIST AI RMF 1.0 / EU AI Act 的控制点映射输出
"""
import json
import os
from typing import Dict, List

# NIST AI RMF 1.0 — 治理(GOV)、映射(MAP)、测量(MEASURE)、管理(MANAGE) 四大功能
NIST_AI_RMF_CONTROLS = {
    "GOV-1": "AI风险治理政策和流程已建立",
    "GOV-2": "AI系统问责制和角色定义明确",
    "GOV-3": "组织内AI风险管理文化已建立",
    "GOV-4": "AI风险管理资源充足",
    "MAP-1": "AI系统上下文和边界已明确",
    "MAP-2": "AI风险分类和优先级已确定",
    "MAP-3": "AI影响评估已完成",
    "MEASURE-1": "AI系统鲁棒性测试已完成",
    "MEASURE-2": "对抗性攻击测试（红队）已完成",
    "MEASURE-3": "公平性和偏见评估已完成",
    "MEASURE-4": "可解释性和可审计性验证已完成",
    "MANAGE-1": "AI风险已持续监控和响应",
    "MANAGE-2": "AI事件响应计划已建立",
    "MANAGE-3": "AI系统退役和停用计划已制定",
}

# EU AI Act — 高风险AI系统要求的关键条款
EU_AI_ACT_CONTROLS = {
    "Art.9": "风险管理体系 — 建立、实施、记录和维护AI风险管理体系",
    "Art.10": "数据治理 — 训练/验证/测试数据集的质量管理",
    "Art.11": "技术文档 — 在系统投放市场前起草技术文档",
    "Art.12": "记录保存 — 高风险AI系统自动记录事件日志",
    "Art.13": "透明度和信息提供 — 向部署者提供清晰的使用说明",
    "Art.14": "人工监督 — 设计适当的人机交互界面",
    "Art.15": "准确性和鲁棒性 — 达到适当的准确性、鲁棒性和网络安全水平",
    "Art.16": "合格评定 — 高风险AI系统投放市场前进行合格评定",
    "Art.17": "质量管理系统 — 建立确保合规的质量管理体系",
}

# VulnCategory → 合规控制点映射
CATEGORY_COMPLIANCE_MAP = {
    "prompt_injection": {
        "nist": ["MEASURE-2", "MANAGE-1"],
        "eu": ["Art.15"],
        "description": "提示注入攻击可直接绕过AI系统的安全防护，违反NIST MEASURE-2对抗性测试要求和EU AI Act Art.15准确性与鲁棒性标准。",
    },
    "system_prompt_leak": {
        "nist": ["MEASURE-4", "MAP-1"],
        "eu": ["Art.11", "Art.13"],
        "description": "系统提示词泄露暴露AI系统内部设计，违反NIST MEASURE-4可审计性要求和EU AI Act Art.11技术文档保护规则。",
    },
    "pii_leak": {
        "nist": ["GOV-2", "MANAGE-2"],
        "eu": ["Art.10"],
        "description": "PII泄露违反NIST GOV-2问责制和EU AI Act Art.10数据治理要求，可能触发GDPR处罚。",
    },
    "jailbreak": {
        "nist": ["MEASURE-2", "MEASURE-1"],
        "eu": ["Art.15", "Art.9"],
        "description": "越狱攻击绕过安全对齐，违反NIST MEASURE-2红队测试和EU AI Act Art.15鲁棒性要求。",
    },
    "harmful_content": {
        "nist": ["MEASURE-3", "MANAGE-1"],
        "eu": ["Art.15", "Art.14"],
        "description": "有害内容生成违反NIST MEASURE-3公平性评估和EU AI Act Art.14人工监督要求。",
    },
    "excessive_agency": {
        "nist": ["MAP-1", "MANAGE-2"],
        "eu": ["Art.14", "Art.15"],
        "description": "Agent过度授权违反NIST MAP-1上下文边界定义和EU AI Act Art.14人工监督要求。",
    },
    "rag_poison": {
        "nist": ["MAP-2", "MEASURE-1"],
        "eu": ["Art.10", "Art.15"],
        "description": "RAG投毒污染知识库，违反NIST MAP-2风险评估和EU AI Act Art.10数据治理标准。",
    },
    "tool_hijack": {
        "nist": ["MAP-1", "GOV-4"],
        "eu": ["Art.15", "Art.14"],
        "description": "工具劫持违反NIST MAP-1上下文边界和EU AI Act Art.15网络安全要求。",
    },
    "mcp_poison": {
        "nist": ["MAP-2", "GOV-4", "MEASURE-2"],
        "eu": ["Art.15", "Art.9", "Art.17"],
        "description": "MCP Server投毒属于供应链攻击，违反NIST MAP-2/MAP风险分类及EU AI Act Art.17质量管理体系要求。",
    },
    "memory_poison": {
        "nist": ["MEASURE-1", "MANAGE-1"],
        "eu": ["Art.15", "Art.9"],
        "description": "记忆污染破坏AI系统长期行为可靠性，违反NIST MEASURE-1鲁棒性测试和EU AI Act Art.9风险管理要求。",
    },
    "email_injection": {
        "nist": ["MEASURE-2", "MAP-1"],
        "eu": ["Art.15"],
        "description": "邮件间接注入属于新型多模态攻击，违反NIST MEASURE-2红队测试和EU AI Act Art.15鲁棒性要求。",
    },
    "agent_hijack": {
        "nist": ["MAP-1", "MEASURE-2", "GOV-2"],
        "eu": ["Art.14", "Art.15", "Art.9"],
        "description": "Agent间通信劫持违反NIST MAP-1边界定义、MEASURE-2安全测试和EU AI Act Art.14人工监督要求。",
    },
    "bias": {
        "nist": ["MEASURE-3"],
        "eu": ["Art.10", "Art.15"],
        "description": "偏见问题违反NIST MEASURE-3公平性评估和EU AI Act Art.10数据治理要求。",
    },
    "hallucination": {
        "nist": ["MEASURE-1", "MEASURE-4"],
        "eu": ["Art.15", "Art.13"],
        "description": "幻觉生成违反NIST MEASURE-1/MEASURE-4准确性和可解释性要求及EU AI Act Art.13透明度要求。",
    },
    "sensitive_info": {
        "nist": ["GOV-2", "MAP-3"],
        "eu": ["Art.10", "Art.13"],
        "description": "敏感信息泄露违反NIST GOV-2问责制和EU AI Act Art.10数据保护要求。",
    },
    "supply_chain": {
        "nist": ["MAP-2", "GOV-4"],
        "eu": ["Art.17", "Art.9"],
        "description": "供应链攻击违反NIST MAP-2风险评估和EU AI Act Art.17质量管理体系要求。",
    },
}

# 按类别分组的结果 -> 合规报告
def generate_compliance_report(results_by_category: Dict[str, list], output_dir: str = ".") -> str:
    """生成合规审计报告 JSON，映射到 NIST AI RMF 和 EU AI Act 控制点。

    Args:
        results_by_category: {"prompt_injection": [ProbeResult, ...], ...}
        output_dir: 输出目录

    Returns:
        生成的报告文件路径
    """
    os.makedirs(output_dir, exist_ok=True)

    compliance = {
        "report_type": "AI Safety Compliance Audit",
        "frameworks": ["NIST AI RMF 1.0", "EU AI Act (High-Risk AI Systems)"],
        "framework_details": {
            "nist_controls": NIST_AI_RMF_CONTROLS,
            "eu_controls": EU_AI_ACT_CONTROLS,
        },
        "findings": [],
    }

    for cat_val, results in results_by_category.items():
        if cat_val not in CATEGORY_COMPLIANCE_MAP:
            continue

        mapping = CATEGORY_COMPLIANCE_MAP[cat_val]
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        findings = {
            "category": cat_val,
            "description": mapping["description"],
            "test_results": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "compliance_status": "PASS" if failed == 0 else "FAIL",
            },
            "nist_controls": [
                {"id": cid, "description": NIST_AI_RMF_CONTROLS.get(cid, "")}
                for cid in mapping["nist"]
            ],
            "eu_controls": [
                {"id": cid, "description": EU_AI_ACT_CONTROLS.get(cid, "")}
                for cid in mapping["eu"]
            ],
            "remediation": _remediation_for_category(cat_val),
        }
        compliance["findings"].append(findings)

    filepath = os.path.join(output_dir, "redteam-compliance.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(compliance, f, ensure_ascii=False, indent=2)
    return filepath


def generate_compliance_summary_text(compliance_data: dict) -> str:
    """生成合规摘要文本（CLI 输出用）"""
    lines = []
    total = len(compliance_data.get("findings", []))
    failed = sum(1 for f in compliance_data.get("findings", []) if f["test_results"]["compliance_status"] == "FAIL")

    lines.append("=" * 60)
    lines.append("  合规审计摘要 — NIST AI RMF 1.0 / EU AI Act")
    lines.append("=" * 60)
    lines.append(f"  涉及控制点类别: {total}")
    lines.append(f"  合规通过: {total - failed}")
    lines.append(f"  不合规: {failed}")

    for f in compliance_data.get("findings", []):
        status = f["test_results"]["compliance_status"]
        marker = "PASS" if status == "PASS" else "FAIL"
        nist_ids = ", ".join(c["id"] for c in f["nist_controls"])
        eu_ids = ", ".join(c["id"] for c in f["eu_controls"])
        lines.append(f"\n  [{marker}] {f['category']}")
        lines.append(f"    NIST: {nist_ids}")
        lines.append(f"    EU:   {eu_ids}")
        lines.append(f"    修复: {f['remediation'][:80]}...")

    return "\n".join(lines)


def _remediation_for_category(category: str) -> str:
    """返回修复建议"""
    suggestions = {
        "prompt_injection": "实施输入清洗、分隔用户指令与系统指令、定期对抗性测试。",
        "system_prompt_leak": "限制系统提示词输出、实施输出过滤、避免敏感配置硬编码。",
        "pii_leak": "实施PII检测和脱敏、设置数据最小化原则、添加输出审计日志。",
        "jailbreak": "增强安全对齐训练、实施多层级安全检测、定期红队测试。",
        "harmful_content": "部署内容安全过滤器、建立内容审核流程、提供用户举报机制。",
        "excessive_agency": "实施最小权限原则、添加人工审批环节、限制高危操作。",
        "rag_poison": "验证知识库内容完整性、实施来源追踪、定期清理污染数据。",
        "tool_hijack": "验证工具调用参数、限制工具调用频率、实施工具操作审计。",
        "mcp_poison": "验证MCP Server签名和来源、限制MCP工具权限范围、实施MCP调用审计。",
        "memory_poison": "验证记忆来源可信度、定期清理可疑记忆、实施记忆访问控制。",
        "email_injection": "过滤邮件中的隐藏标签和指令、实施发件人验证、独立处理邮件内容。",
        "agent_hijack": "验证子Agent返回结果的完整性、实施Agent间通信加密和签名验证。",
        "bias": "使用多样化训练数据、定期偏见评估、实施公平性指标监控。",
        "hallucination": "引入事实核查机制、限制不确定回答、提供信息来源追溯。",
        "sensitive_info": "实施数据分类分级、加密敏感数据、建立数据防泄露机制。",
        "supply_chain": "验证第三方组件来源、建立供应链安全审查流程、定期漏洞扫描。",
    }
    return suggestions.get(category, "实施安全最佳实践并定期进行安全审计。")
