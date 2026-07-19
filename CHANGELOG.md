# Changelog

## [Unreleased]

### Added
- 6 大安全测试方向补全（94 条探测）
- PII 正则检测模块（14 种模式）
- 合规审计报告（NIST AI RMF 1.0 / EU AI Act）
- SQLite 持久化与 history/diff/trend 命令

## [0.4.0] - 2026-07-16

### Added
- Agent 安全测试能力：MCP 投毒、记忆污染、邮件注入、Agent 通信劫持
- 4 组新探测定制预设（mcp/memory/agent/email，共 12 条）
- excessive_agency 扩展 4 条探测
- 合规审计报告模块
- SQLite 持久化存储（history/diff/trend CLI 子命令）

## [0.3.0] - 2026-07-15

### Added
- Vision 模型自动检测与真实图片注入攻击
- AnthropicAdapter 自定义 base_url 支持
- E2E 全流程测试套件（135 条测试）
- Pollinations 免费模型适配器

## [0.2.0] - 2026-07-14

### Added
- YAML 驱动探测定制系统与预设组
- 8 种偏门攻击向量（PDF/图片/URL/Markdown/工具输出/分块投递/Unicode同形字/Token走私）
- 中文特色攻击模板（文言文绕过、谐音字、社会工程）
- 变异引擎（9 种算子）
- 多轮对话探测

## [0.1.0] - 2026-07-13

### Added
- 初始版本
- OWASP LLM Top 10 核心探测（19 条）
- 关键词裁判 + LLM-as-Judge + 混合裁判
- JSON/HTML/JUnit 报告输出
- 多模型适配器（OpenAI/Anthropic/本地Mock）
