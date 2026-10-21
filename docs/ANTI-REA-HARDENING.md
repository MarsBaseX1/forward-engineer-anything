# FEA 对 REA 类 AI 辅助逆向的防护层策略

本文档记录 FEA 从「发布卫生检查」向「提高分析与篡改成本的保护工程框架」演进的具体策略。

**核心原则：不承诺软件无法被逆向，而是系统性抬高 REA / Ghidra / Hopper / IDA + Agent 的分析成本、证据质量和复现难度。**

参考对象：[morluto/rea](https://github.com/morluto/rea) 及类似通过 MCP 连接逆向工具的 Agent 工作流。

## 1. 资产暴露层（已实现）

- FEA001–FEA005：Source Map、私钥候选、内部配置、调试资源、测试资产。
- FEA006：客户端授权/许可判断。
- FEA007：硬编码密钥/令牌候选。
- FEA008：未混淆业务逻辑指示。
- FEA009：客户端敏感数据暴露（`window.__STATE__`、`localStorage` token 等）。

CI 门禁覆盖最终产物（解包目录 / ASAR）。

## 2. 构建与交付层（部分实现）

- Electron Forge JSON 自动化：`packagerConfig.asar = true` + 推荐完整性 Fuses（`EnableEmbeddedAsarIntegrityValidation`、`OnlyLoadAppFromAsar`）。见 [PROTECT-AUTOMATION.md](PROTECT-AUTOMATION.md)。
- 可选混淆建议生成器（`fea obfuscate`）。
- 服务端迁移建议生成器（`fea migrate`）。

## 3. 运行时与信任边界层（建议已提供）

- 服务端授权为唯一权威：已有授权示例与迁移建议。
- 客户端仅做演示性判断；真实状态与许可证由服务端持有。
- 签名与公证：Windows Authenticode 状态检查已实现；macOS 仍在路线图。

## 4. 对抗评测层（骨架已提供）

- Arena 支持可信任本地适配器。`demo/rea-observer.mjs` 提供只读观察骨架。
- 见 [REA-ADAPTER.md](REA-ADAPTER.md) 了解如何替换为真实 REA 适配器。
- 明确声明：成功率下降不等于无法逆向。

## 5. 优先级与实现状态

1. **短期**（已完成）：扩展 Audit 规则（FEA006–FEA009）；完善 Forge ASAR + 完整性 Fuses 自动化。
2. **中期**（已完成骨架）：可选混淆建议 + 服务端迁移建议生成器；REA 风格适配器对接文档与骨架。
3. **长期**（路线图）：原生（PE / Mach-O / .NET）适配器、运行时防护插件接口、可复现的公开对抗基准。

## 边界与声明

- 客户端代码一旦交付，就可能被分析。最终保护依赖架构（敏感逻辑不在客户端）而非单纯混淆。
- 任何加固都有兼容性、性能与维护代价，必须提供回滚与测试。
- FEA 不会自动执行未知脚本或修改已签名产物。
- 对抗评测必须使用合法、受授权的目标与隔离环境。

详见 [ROADMAP.md](ROADMAP.md)、[THREAT_MODEL.md](THREAT_MODEL.md) 与 [PROTECT-AUTOMATION.md](PROTECT-AUTOMATION.md)。
