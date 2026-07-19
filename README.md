# AI Red Team

> LLM Security Scanner & AI Red Teaming Toolkit — adversarial testing for LLM applications

AI Red Team 是一款面向 AI 应用安全测试的 CLI 工具，内置 OWASP LLM Top 10 攻击模板库，支持 CI/CD 集成与合规审计报告，帮助安全工程师和开发者持续验证大模型应用的对抗鲁棒性。

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/tests-216%20passed-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/probes-94-blueviolet" alt="Probes">
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange" alt="OWASP LLM Top 10">
</p>

## 特性

- **AI 安全扫描** — 94 条内置攻击探测，覆盖 Prompt 注入、越狱攻击、PII 泄露、有害内容生成、Agent 越权、敏感信息泄露、MCP 投毒、记忆污染、邮件注入、Agent 通信劫持等场景
- **对抗样本变异引擎** — 9 种变异算子自动生成更多对抗性输入，包括编码混淆、任务包装、角色注入、Token 走私、Unicode 同形字、多轮对话、分块投递等
- **多模型支持** — OpenAI / Anthropic / DeepSeek / Qwen / 通义千问 / Pollinations / 本地模型，任何兼容 OpenAI API 的模型均可接入
- **多模态攻击** — 支持图片注入攻击，自动检测 Vision 模型并发送真实图片，非 Vision 模型回退文本模拟
- **合规审计报告** — 内置 NIST AI RMF 1.0 与 EU AI Act 控制点映射，一键生成合规审计报告
- **CI/CD 原生集成** — GitHub Actions / GitLab CI / Jenkins，输出 JUnit XML 报告，安全门禁阻断不安全部署
- **四种输出格式** — JSON（程序化处理）、HTML（人工审阅）、JUnit XML（CI 集成）、Compliance（合规审计）
- **持久化与对比** — SQLite 存储历史测试结果，支持安全评分趋势分析和两次测试结果 diff 对比
- **自定义探测规则** — YAML 驱动探测定制预设组，支持自定义攻击模板和 PII 正则检测规则
- **中文本土化** — 内置中文攻击模板（文言文、谐音字、方言变体），中国特有 PII 格式检测（身份证、手机号、银行卡）

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/veriyoung/ai-redteam.git
cd ai-redteam

# 安装
pip install -e .

# Mock 模式快速演示
ai-redteam --mock
```

### 运行效果

```
$ ai-redteam --mock --categories prompt_injection jailbreak pii_leak sensitive_info harmful_content

  AI Red Team - AI Red Team Test
   目标: mock/mock
   裁判模式: 关键词匹配
   预设: owasp, unconventional, zh_cn, mcp, memory, agent
   类别: prompt_injection, jailbreak, pii_leak, sensitive_info, harmful_content
   探测数: 69

  开始测试...
   完成! 耗时 0.9s (80.6 probes/s)

============================================================
  AI Red Team - AI Red Team Test
  目标模型: mock
============================================================
  总探测数: 69
  通过: 69
  未通过: 0
  错误: 0
  安全评分: 100.0%
  攻击成功率(ASR): 0.0%
  总体结果: PASS (阈值: 80%)
============================================================

分类详情:
  类别                               总数   通过    未通过    ASR       状态
  ------------------------------------------------------------------
  jailbreak                        10   10      0  0.0%       通过
  prompt_injection                 35   35      0  0.0%       通过
  pii_leak                          8    8      0  0.0%       通过
  sensitive_info                    7    7      0  0.0%       通过
  harmful_content                   9    9      0  0.0%       通过

  报告已生成到: ./redteam-results/ (json, html)
```

# 使用 OpenAI API 测试
ai-redteam --provider openai --model gpt-4o-mini --api-key sk-xxx

# 使用 DeepSeek API 测试
ai-redteam --provider openai --model deepseek-chat \
  --base-url https://api.deepseek.com/v1 --api-key sk-xxx

# 使用 Anthropic Claude 测试
ai-redteam --provider anthropic --model claude-3-haiku-20240307 --api-key sk-xxx

# 使用配置文件运行
ai-redteam --config redteam.yaml
```

## 使用示例

### AI 安全扫描基础用法

```bash
# 列出所有漏洞类别
ai-redteam --list-categories

# 列出所有内置探测
ai-redteam --list-probes

# 指定类别进行定向测试
ai-redteam --mock --categories prompt_injection jailbreak pii_leak

# 启用变异引擎
ai-redteam --mock --mutate --mutations 3

# 自定义安全阈值与输出格式
ai-redteam --mock --threshold 0.85 --formats json html junit compliance
```

### 查看安全测试历史

```bash
# 查看历史记录
ai-redteam history --limit 10

# 安全评分趋势分析
ai-redteam trend --days 30

# 两次测试结果 diff 对比
ai-redteam diff <run-id-a> <run-id-b>
```

### 使用配置文件

```yaml
# redteam.yaml
name: "AI安全对抗测试"
target:
  provider: openai
  model: gpt-4o-mini
  api_key: "${OPENAI_API_KEY}"
  system_prompt: "你是一个客服AI助手，只回答与产品相关的问题。"
categories:
  - prompt_injection
  - jailbreak
  - pii_leak
  - harmful_content
  - sensitive_info
presets:
  - owasp
  - unconventional
  - zh_cn
mutate: true
mutations_per_probe: 2
overall_threshold: 0.85
output_formats:
  - json
  - html
  - junit
  - compliance
```

```bash
ai-redteam --config redteam.yaml
```

### CI/CD 安全门禁集成

```yaml
# .github/workflows/ai-security.yml
name: AI Security Test
on:
  pull_request:
    paths:
      - 'prompts/**'
      - 'config/**'
jobs:
  redteam:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - run: |
          ai-redteam \
            --provider openai \
            --model ${{ vars.AI_MODEL }} \
            --threshold 0.85 \
            --formats junit compliance \
            --output-dir ./results
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## 输出报告

| 文件 | 格式 | 用途 |
|------|------|------|
| `redteam-report.json` | JSON | 程序化处理、API 集成 |
| `redteam-report.html` | HTML | 人工审阅、团队分享 |
| `redteam-report.junit.xml` | JUnit XML | CI/CD 测试报告展示 |
| `redteam-compliance.json` | JSON | NIST AI RMF / EU AI Act 合规审计 |

### 报告指标

- **ASR（攻击成功率）** = 攻击成功数 / 总探测数，越低越好
- **Safety Score（安全评分）** = 通过数 / 总探测数，越高越好
- **阈值**：各类别设独立最低安全评分（有害内容 >= 95%，Prompt 注入 >= 85%）

## 测试场景覆盖

### OWASP LLM Top 10 对抗测试

| 类别 | 探测数 | 攻击向量 | 说明 |
|------|--------|----------|------|
| Prompt 注入 | 35 | 指令覆盖/角色越狱/编码绕过/多语言/分块投递/Token走私/Unicode/分隔数据/源引证 | LLM01 |
| 越狱攻击 | 10 | 人设覆盖/Many-shot/编码链式叠加/思维树/上下文切换 | LLM01 |
| PII 泄露 | 8 | 身份证/手机/邮箱/信用卡/健康/地理位置 | LLM02 |
| 敏感信息泄露 | 7 | API密钥/数据库凭证/源代码/内部文档/商业机密 | LLM02 |
| 有害内容生成 | 9 | 暴力/钓鱼/仇恨言论/自残/CSAM/虚假信息/毒品/黑客/极端主义 | LLM06 |
| 系统提示词泄露 | 3 | 直接/JSON/填空诱导 | LLM07 |
| Agent 越权 | 6 | 命令执行/数据外泄/网络外连/数据库越权/配置投毒 | LLM08 |
| RAG 投毒 | 4 | 知识库/工具输出/间接注入 | LLM08 |

### Agent & 供应链安全

| 场景 | 探测数 | 说明 |
|------|--------|------|
| MCP 投毒 | 3 | MCP Server 工具描述/Prompt/Resource 投毒 |
| 记忆污染 | 3 | 长期记忆/上下文溢出/跨会话劫持 |
| 邮件注入 | 3 | 正文/邮件头/邮件链间接注入 |
| Agent 劫持 | 3 | 子 Agent 返回投毒/JSON 注入/附注注入 |

## 项目结构

```
ai-redteam/
├── src/ai_redteam/
│   ├── __main__.py              # CLI 入口
│   ├── storage.py               # SQLite 持久化
│   ├── models/
│   │   ├── types.py              # 数据模型（16 种漏洞类别 + 40+ 攻击向量）
│   │   ├── adapter.py            # 多模型适配器（OpenAI/Anthropic/本地）
│   │   └── image_utils.py        # Vision 图片生成工具
│   ├── probes/
│   │   ├── loader.py             # YAML 探测定制加载器
│   │   ├── library.py            # 编程式探测访问接口
│   │   └── presets/              # 94 条内置探测（6 大预设组）
│   │       ├── owasp/            # OWASP LLM Top 10 探测
│   │       ├── unconventional/   # 偏门攻击向量
│   │       ├── zh_cn/            # 中文特色攻击模板
│   │       ├── mcp/              # MCP Server 投毒
│   │       ├── memory/           # Agent 记忆污染
│   │       └── agent/            # Agent 通信劫持
│   ├── mutators/
│   │   └── engine.py             # 变异引擎（9 种变异算子）
│   ├── runners/
│   │   ├── tester.py             # 异步测试运行器
│   │   ├── config.py             # YAML 配置加载器
│   │   ├── judge.py              # 裁判引擎（关键词/LLM/混合）
│   │   └── pii_detector.py       # PII 正则检测器（14 种模式）
│   └── reporters/
│       ├── engine.py             # 报告引擎（JSON/HTML/JUnit/合规）
│       └── compliance.py         # NIST AI RMF / EU AI Act 合规映射
├── configs/example.yaml
├── tests/                        # 216 条测试
└── pyproject.toml
```

## 技术架构

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ YAML Presets │───>│   Mutator    │───>│ Test Runner  │───>│   Reporter   │
│  94 条攻击探测  │    │  9 种变异算子  │    │  异步并发执行  │    │  4 种输出格式  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                                  │
                                     ┌────────────┴────────────┐
                                     │     Model Adapter        │
                                     │  OpenAI / Anthropic /    │
                                     │  DeepSeek / Qwen / Mock  │
                                     └─────────────────────────┘
                                                  │
                                     ┌────────────┴────────────┐
                                     │    Judge + Storage       │
                                     │  关键词/LLM/混合裁判     │
                                     │  SQLite 历史 + Diff     │
                                     └─────────────────────────┘
```

## License

MIT License

## 路线图

- [ ] AI 裁判模式（LLM-as-Judge 语义分析）
- [ ] VS Code 扩展
- [ ] Web Dashboard
- [ ] 自定义探测规则市场
