# FEA 对 REA 类 AI 辅助逆向的防护层策略

本文档记录 FEA 从「发布卫生检查」向「提高分析与篡改成本的保护工程框架」演进的具体策略。

**核心原则：不承诺软件无法被逆向，而是系统性抬高 REA / Ghidra / Hopper / IDA + Agent 的分析成本、证据质量和复现难度。**

参考对象：[morluto/rea](https://github.com/morluto/rea) 及类似通过 MCP 连接逆向工具的 Agent 工作流。

## 1. 资产暴露层（已实现 + 扩展）

- 继续强化 FEA001–FEA005：Source Map、私钥候选、内部配置、调试资源、测试资产。
- 新增规则：检测未混淆的业务逻辑模块、硬编码字符串、客户端可观察的授权判断、API 端点与密钥派生逻辑。
- CI 门禁必须覆盖最终产物（解包目录 / ASAR / 安装包提取内容），而不只是源码目录。

## 2. 构建与交付层（Protect 演进）

- Electron Forge / electron-builder 自动化：禁用 Source Map、分离调试资产、强制 ASAR integrity、启用 Electron Fuses（RunAsNode=false、EnableNodeCliInspectArguments=false 等）。
- 引入可选混淆适配器（javascript-obfuscator、bytenode、或编译到 WASM/Native 模块），但必须提供回滚与性能回归测试。
- 代码分割：将核心算法、许可证校验、敏感业务规则从客户端迁移到服务端；客户端仅保留演示与缓存。
- 动态加载与延迟解密：关键模块在运行时从受信源获取，并与设备/用户绑定。

## 3. 运行时与信任边界层

- 服务端授权为唯一权威：所有敏感操作必须经服务端校验与额度控制（已有授权示例，需产品化）。
- 客户端仅做演示性判断；真实状态与许可证由服务端持有。
- 引入设备指纹、运行时环境检测（可选、非强制），但明确标注兼容性代价。
- 签名与公证：完善 Windows Authenticode 与 macOS codesign/公证检查，并验证最终产物完整性。

## 4. 对抗评测层（Arena 演进）

- 支持接入真实 REA / Ghidra / Hopper 适配器（需用户合法安装并显式授权）。
- 任务示例：提取关键字符串、重建一个可观察业务功能、绕过客户端授权判断、定位敏感配置。
- 固定模型、工具版本、预算与种子，公开成功率、耗时、成本对比（基线 vs 加固）。
- 明确声明：成功率下降不等于无法逆向；只证明在该任务、该预算下的成本变化。

## 5. 优先级与下一步实现

1. **短期**：扩展 Audit 规则覆盖未混淆逻辑与硬编码敏感信息；完善 Forge ASAR integrity 与 Fuse 自动化。
2. **中期**：可选混淆适配器 + 服务端迁移建议生成器；真实 REA 适配器接入 Arena。
3. **长期**：原生（PE / Mach-O / .NET）适配器、运行时防护插件接口、可复现的公开对抗基准。

## 边界与声明

- 客户端代码一旦交付，就可能被分析。最终保护依赖架构（敏感逻辑不在客户端）而非单纯混淆。
- 任何加固都有兼容性、性能与维护代价，必须提供回滚与测试。
- FEA 不会自动执行未知脚本或修改已签名产物。
- 对抗评测必须使用合法、受授权的目标与隔离环境。

详见 [ROADMAP.md](ROADMAP.md)、[THREAT_MODEL.md](THREAT_MODEL.md) 与 [PROTECT-AUTOMATION.md](PROTECT-AUTOMATION.md)。
