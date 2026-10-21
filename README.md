<p align="center">
  <img src="assets/fea-icon.png" width="160" alt="FEA：青绿盾牌、抽象 F 与向前箭头">
</p>

# Forward Engineer Anything（FEA）

[简体中文](README.md) · [English](README.en.md)

**正向构建，纵深保护。**

*Build forward. Raise the cost of reverse engineering.*

面向 Windows / macOS 桌面软件作者的开源防护工程框架：减少随客户端发布的秘密，改进授权与发布边界，并用可复验的证据衡量 AI 辅助逆向下的剩余风险。

FEA 将防逆向工作融入日常软件交付：开发者声明需要保护的资产，工具检查发布资源、提出构建加固建议，再以发布验证和对抗实验衡量效果。项目服务独立开发者、桌面软件团队与应用安全工程师，首先覆盖 Electron，随后按适配器扩展到更多桌面技术栈。

**English introduction:** Forward Engineer Anything is an open-source protection engineering framework for Windows and macOS desktop apps. It helps developers reduce accidental exposure, plan supported build hardening, verify release integrity, and measure resilience against AI-assisted analysis with reproducible evidence.

> 当前状态：项目设计稿。此目录包含产品设计、威胁模型和路线图，尚无可运行 CLI、npm 包或 GitHub Action。以下功能与命令均为拟议接口。

## 为什么做 FEA

[REA 官方项目](https://github.com/morluto/rea)通过 MCP / CLI 连接软件分析工具。FEA 面向软件作者，帮助回答三个问题：发布出去的东西暴露了什么，哪些保护措施确实有效，下一次发布是否又引入了风险。

FEA 保留 “Anything” 作为适配器扩展愿景。每个版本只对明确列出的输入格式和检查项负责。

**FEA 的工程目标是降低泄漏与未授权使用风险、提高分析和篡改成本。** 已交付给用户执行的逻辑仍可能被分析；纯离线功能仍可能被修改；可观察的功能与界面仍可能被重新实现。混淆与防篡改只是附加防御层，不能替代正确的信任边界。[OWASP 对纵深防护的说明](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)面向移动端，FEA 参考其原则，不宣称获得桌面软件安全认证。

## 保护什么

| 目标 | FEA 的设计能力 | 需要承认的边界 |
|---|---|---|
| 发布信息暴露 | 检查 source map、私钥候选、内部配置和调试资产 | 未发现问题不等于不存在秘密；Electron 的 JavaScript 不能简单按泄漏处理 |
| 商业算法与模型 | 识别敏感资产，提出服务端隔离或减少客户端交付的建议 | 需要在客户端执行的算法与模型不能保证永久保密 |
| 授权与付费能力 | 提供服务端授权设计和负面测试参考 | 客户端显示“已授权”不能证明服务端应放行；纯离线授权存在绕过边界 |
| 发布真实性与完整性 | 接入平台签名检查、构建清单和成熟更新机制 | 签名不加密代码，也不保证攻击者无法在自己的设备运行修改版本 |
| AI 辅助分析成本 | 对自有样本比较加固前后的任务成功率、成本与兼容性 | 有限预算内未成功不等于永远无法逆向 |

服务端敏感操作应独立检查权限，不依赖客户端的判断。[MITRE CWE-602](https://cwe.mitre.org/data/definitions/602.html)说明了依赖客户端实施服务端安全检查的风险。

## 四个模块

| 模块 | 作用 | 首次交付目标 |
|---|---|---|
| **Audit** | 对发布资源做只读检查，输出规则、证据、置信度和覆盖范围 | v0.1 |
| **Protect** | 为受支持构建链提出可审查的加固补丁，保留回滚与功能验证步骤 | v0.2 |
| **Verify** | 执行 CI 策略门禁；随后扩展到最终包签名、发布清单与运行验证 | v0.1 策略门禁；v0.2 平台验证 |
| **Arena** | 用自有演示应用和固定预算比较人工 / AI 辅助分析效果 | v0.3 |

AI 负责解释证据和提出修改建议；确定性规则负责判定发布策略。扫描与 CI 门禁不依赖模型服务。

## 首版：先覆盖一条桌面发布链

v0.1 面向 Windows / macOS 上的 **Electron 发布资源目录**：构建流水线产生的待打包资源树，或由软件作者提供的已解包资源树。两种输入都必须标记来源阶段。

首版设计包含本地 CLI、五类暴露检查、JSON / SARIF 报告、配置化 CI 门禁，以及带已知答案的测试夹具。首版不直接读取 ASAR，不检查完整 EXE、MSI、DMG 或原生二进制，也不证明最终安装包与待打包资源完全对应。

ASAR 是归档格式，不能作为代码保密边界。[Electron ASAR 文档](https://www.electronjs.org/docs/latest/tutorial/asar-archives)说明了归档内容的读取方式。原始归档与最终包检查在 v0.2 单独实现和验证。

## 拟议使用方式

以下是接口设计，当前不能执行；没有需要安装的 FEA 软件包。

```text
# v0.1：声明项目与输入阶段
fea init --profile electron-resources

# v0.1：扫描开发者提供的发布资源目录
fea scan ./release-resources --config fea.yml --out ./.fea/reports/baseline

# v0.1：对已有报告执行策略，不重新扫描
fea verify ./.fea/reports/baseline/report.json --policy fea.yml

# v0.2：提出构建配置补丁，供开发者审查
fea plan ./.fea/reports/baseline/report.json --out ./.fea/plans/release

# v0.3：比较同一演示应用两种构建的对抗评测
fea arena compare ./baseline ./hardened --suite ./benchmarks/demo-suite.json
```

一条完整防护流程是：声明资产 → 检查暴露 → 修改构建或架构 → 重建并验证功能 → 签名与封装 → 检查最终产物 → 对抗评测。v0.1 先交付“检查暴露与策略门禁”这一段。

## 用证据展示价值

公开演示围绕同一个自有 Electron 应用展开：基线包含合成私钥、source map 和内部配置；改进版减少发布资产，并将一个演示敏感操作放到独立授权服务后。

基准分别展示暴露检查结果、未授权请求测试、平台完整性检查和有限预算的分析结果。后面三项按里程碑加入。所有结果保留版本、输入摘要、覆盖范围、失败情况与功能代价，不发布“不可破解”徽章或通用防逆向总分。

## 文档

- [完整产品与架构设计](docs/superpowers/specs/2026-10-21-fea-design.md)
- [威胁模型与保护边界](docs/THREAT_MODEL.md)
- [版本范围与验收标准](docs/ROADMAP.md)
- [项目图标与设计说明](assets/ICON.md)

## 开源方式

GitHub 仓库名为 `forward-engineer-anything`，简称 `FEA`。CLI 与软件包名称尚未核验或注册。

项目采用 [Apache-2.0](LICENSE) 许可证。公开规则、适配器、验证协议和基准；软件作者的业务源码、签名私钥、客户数据与服务端秘密分别管理，工具开源不要求被保护软件开源。后续引入第三方代码与工具时，分别保留其许可证和必要声明。

项目与 REA 独立，无隶属或认可关系。防护验证针对自有或获授权的软件；项目文案尊重互操作、审计与安全研究的正当用途。
