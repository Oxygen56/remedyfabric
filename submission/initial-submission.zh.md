# GOAI 2026 Agent Infra 初始提交包

## 项目名称

RemedyFabric

## 项目简介（500 字以内）

RemedyFabric 是面向软件仓库故障的证据优先多智能体恢复基础设施。Triage Agent 复现并提取故障证据，Repair Agent 通过可复用 Skill 生成类型化最小补丁，Governor Agent 以失败关闭策略限制路径、密钥和变更半径，Verifier Agent 运行可见测试与独立不变量；验证失败即字节级回滚。所有状态、命令、决策、补丁、耗时和成本写入 SHA-256 链式回执。项目提供 AgentTeams 五角色 CRD、Apache-2.0 代码、零密钥离线 Demo、8 场景透明基准及单 Agent、去治理、去验证、去回滚消融。当前证据仅证明公开自建基准：完整方案任务成功率和可恢复故障修复率均为 100%，安全违规提交率为 0%；不宣称生产采用或外部 SOTA。

## 公开材料

- 代码仓库：https://github.com/Oxygen56/remedyfabric
- 发布包：https://github.com/Oxygen56/remedyfabric/releases/tag/v0.1.0
- 持续集成：https://github.com/Oxygen56/remedyfabric/actions/runs/31328034916
- 技术提案：`output/pdf/remedyfabric-goai-2026-proposal.pdf`
- 演示视频：`artifacts/remedyfabric-demo.mp4`
- 基准原始结果：`artifacts/benchmark.json`

## 披露边界

- 运行时代码仅使用 Python 标准库，无商业模型、商业 API 或付费数据依赖；离线 Demo 成本为 0 美元。
- Codex 用于项目设计、实现、测试、文档、基准与演示材料制作；公开提交中的 AI Disclosure 字段必须由参赛者确认最终措辞后再填写。
- 基准场景由项目作者构造并公开，不代表独立第三方评测、生产稳定性或行业最优。
- 源码采用 Apache-2.0；第三方工具和字体仅用于开发或演示生成，详见 `docs/DISCLOSURE.md`。

## 时间门

- 内部冻结：2026-08-15 23:59（北京时间）
- 官方初赛截止：2026-08-16 23:59（北京时间；提交前仍需在官方页面再次核验）
