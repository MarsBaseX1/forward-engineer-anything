> **v1.0.0 stable (2026-10-21):** FEA is now a complete anti-REA hardening framework for Electron. Core audit rules (FEA001–FEA009), Forge automation, suggestion generators, and Arena protocol are stable. See [CHANGELOG.md](../CHANGELOG.md) and [ANTI-REA-HARDENING.md](ANTI-REA-HARDENING.md).

# FEA 版本路线图

**v1.0.0** 已于 2026-10-21 正式发布。以下记录已稳定的能力与后续规划。详细边界请参阅 [IMPLEMENTATION.md](../IMPLEMENTATION.md)。

详细防护策略见 [ANTI-REA-HARDENING.md](ANTI-REA-HARDENING.md)。

## v1.0.0 已稳定能力

- **Audit**：FEA001–FEA009 规则（Source Map、私钥标记、内部配置、调试/测试资源、客户端授权、硬编码密钥、未混淆逻辑、客户端数据暴露）
- 受限目录与 ASAR 扫描 + 策略验证 + CI 门禁
- Electron Forge JSON 受控自动化（`protect`：ASAR + 完整性 Fuses，外部备份 + 精确回滚）
- 建议生成器：`migrate`、`obfuscate`、`runtime`
- Arena 配对评测协议（可信本地适配器执行器 + 外部 JSONL 证据导入）
- SARIF 2.1.0 导出
- 发布准备度与受限安装包识别检查

**边界（仍有效）：** 不承诺无法逆向；ASAR 不是加密；不自动改写业务代码；Arena 与建议不构成逆向抵抗证明。

## 后续规划

### 短期 / 中期（持续优化）

- 规则精细度与误报控制改进
- 更多构建工具适配器（仍保持受控、可审查）
- 发布可信性检查覆盖扩展
- npm TAR 深度内容审计（有界、只读、不解包、不执行）并在独立 Runner 上复验
- 原生 EXE/MSI 的 Authenticode 发布者固定；DMG/PKG 的 Team ID、Gatekeeper 与公证票据门禁
- 原生安装包 payload 的格式化、非执行式解包审计仍需按实际分发格式实现；npm Registry 发布保持单独审批，不自动触发

### 长期

- 原生适配器（.NET、PE / Mach-O 等），各自独立支持矩阵
- 运行时防护插件接口
- 可复现的公开对抗基准（需授权目标与独立验证）
- 安全更新框架集成参考（如 TUF）

## GitHub 发布准备

- Apache-2.0 协议
- 中英文 README、图标、贡献指南
- 稳定版本号与 CHANGELOG
- 发布首页已区分“已实现”与“边界声明”
- 无独立安全认证声明

参阅 [THREAT_MODEL.md](THREAT_MODEL.md) 了解威胁模型。
