# FEA Arena — REA 风格适配器对接说明（实验性）

本文档说明如何在 Arena `execute` 中使用可信任的本地适配器，观察静态发现是否仍然可见（从而衡量加固是否抬高了 REA 类工具的分析成本）。

**重要边界：**

- 仓库内置适配器（`demo/rea-observer.mjs`）**不调用 AI 模型**，也不连接真实 REA。
- 真实 REA / Ghidra / Hopper 适配器必须由操作者自行安装、审核并在隔离环境中运行。
- 成功率下降不等于软件无法被逆向。

## 内置观察器

`demo/rea-observer.mjs` 支持以下任务 ID（对应 FEA 规则）：

| 任务 ID | 规则 |
|---------|------|
| `observe-source-map` | FEA001 |
| `observe-client-auth` | FEA006 |
| `observe-hardcoded-secret` | FEA007 |
| `observe-unobfuscated` | FEA008 |

使用方式（需先运行 `npm run demo` 生成 ASAR）：

```bash
node src/cli.mjs arena execute \
  --suite demo/arena-suite-anti-rea.json \
  --baseline demo/generated/baseline/app.asar \
  --hardened demo/generated/hardened/app.asar \
  --adapter demo/rea-observer.mjs \
  --engine demo/arena-executor-engine.json \
  --out demo/generated/reports/arena-anti-rea \
  --i-own-artifacts
```

## 接入真实 REA 适配器的要求

1. 适配器必须是本地 `.mjs` 文件，从 stdin 读取一行 JSON：
   ```json
   {"formatVersion":1,"variant":"baseline"|"hardened","taskId":"...","seed":0,"artifactPath":"...","budget":{...}}
   ```
2. 向 stdout 写入一行 JSON 并以退出码 0 结束：
   ```json
   {"status":"success"|"failure"|"timeout","costUsd":0.0}
   ```
3. 不得修改传入的产物；不得读取任意未授权路径。
4. 真实 REA 调用必须在适配器内部完成，FEA 不会代为启动外部进程。
5. 必须显式传递 `--i-own-artifacts`，并在隔离环境中运行。

完整执行器限制见 [ARENA-EXECUTOR.md](ARENA-EXECUTOR.md)。
