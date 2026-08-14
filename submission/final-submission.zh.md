# GOAI 2026 Agent Infra 冠军版表单真源

> 当前是冻结前真源，不是可直接粘贴的提交稿。只有
> 公开 v0.2.0 release ZIP 内的 `champion-gate.json` 为 `ready`、严格
> AgentTeams 凭据有效、同一 ZIP 内四个后置凭据全部通过、
> `clean-replay.json` 可追溯到精确冻结 HEAD 的公开 CI artifact、且第二次提交页面实时
> 核验无新增披露字段后，才能复制以下内容。若表单出现 AI Disclosure，
> 必须停在填写前，由参赛者查看原字段并确认措辞。

## 项目名称

RemedyFabric

## 项目简介（500 中文字以内）

RemedyFabric 是“修复 Agent 自己失效时仍能安全恢复”的开源基础设施。3 个 Worker 在隔离副本提案，2 个 Verifier、Challenger、Governor 与单独授权的 Release Manager 绑定测试、策略、快照和补丁，法定人数通过后才写入真实工作区。22 次临时仓库试验中，8 类单 Worker 故障恢复率 100%、不安全发布 0；13 个越界/控制故障全部安全关闭，授权前写入和外部字节变化均为 0。另有 20,748 状态穷举及 30 例可追溯 OSS 协议对照（23 例单故障、7 例越界）。仅当严格凭据有效时，还证明官方 AgentTeams v1.2.2 Controller、Manager 与 8 个 Worker 容器完成 operator-captured 类型化闭环；不宣称 LLM 自主编排、通用 BFT、独立故障域或生产可靠性。Apache-2.0。

## 公开材料

- 仓库：https://github.com/Oxygen56/remedyfabric
- 发布：https://github.com/Oxygen56/remedyfabric/releases/tag/v0.2.0
- 持续集成：公开 v0.2.0 release ZIP 内的 `public-ci.json` 记录精确 Actions 运行 URL；只认该冻结 HEAD 的已完成成功运行。
- 提交包 SHA-256：不自嵌入 ZIP；打包后由提交回执记录实际 SHA-256。
- 技术提案：`output/pdf/remedyfabric-goai-agent-infra-champion.pdf`
- 演示视频：`artifacts/remedyfabric-champion-demo.mp4`（最终合同为无声、字幕优先）
- 冠军门禁：仅认公开 v0.2.0 release ZIP 内的 `champion-gate.json`；仓库或本地同名文件不是权威凭据。

冻结 HEAD 后才能生成 `clean-replay.json`、`public-ci.json`、
`champion-evidence.json` 和 `champion-gate.json`；把它们提前提交进 HEAD
会改变它们要绑定的对象。因此它们只在公开 release ZIP
中构成权威套件，clean receipt 还必须与公开 CI artifact 一致；
任一载体或凭据缺失即为 pending。

## 团队信息

- 项目所有者：Oxygen56
- 赛道：新智基座（Agent Infra）
- 开源许可：Apache-2.0

## AI / 模型 / 工具披露草案

- Codex 广泛协助研究、架构、实现、测试、文档、审计和材料制作；Codex 不参与确定性离线运行时。
- 确定性核心不调用模型、Codex、外部 API 或私有数据，模型/API 费用为 0 美元。
- 仅当 `artifacts/agentteams-live-evidence.json` 严格有效时，官方 live 路径才披露为：AgentTeams v1.2.2 Controller + Manager + 8 Worker 容器；adapter-assisted、operator-captured Matrix 类型化协议；两个 proposer 真实执行 recovery Skill，两个 Verifier、lead reviewer、Challenger、Governor 与 Release Manager 执行绑定角色工具，Release Manager 真实调用 `QuorumGate`。这不是 LLM 自主端到端编排声明。
- live 路径使用本地 Ollama `gpt-oss:20b`，摘要 `17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`，20.9B、MXFP4、Apache-2.0；模型/API 成本 0 美元，使用本地算力。早期 qwen 模型仅用于失败诊断，不计入任何成功结果或指标。
- 官方 Alibaba Cloud `alibabacloud-resourcecenter-search` Skill 已固定并完成包校验；严格凭据最多证明 adapter 执行无凭据预检并在请求前退出，没有读取凭据、没有云查询、没有云结果或费用。
- 若官方表单出现专门 AI Disclosure 字段：停止自动填写，保留字段原文并由参赛者确认最终回答。

## 提交前核对

- [ ] 页面仍显示可提交，截止仍为 2026-08-16 23:59（北京时间）。
- [ ] 当前为第 2/3 次机会；第 3 次仅留给致命纠错。
- [ ] 公开 release ZIP 内 champion gate、manifest/hash、AgentTeams 严格验证、clean replay、public CI、delivery QA 全部通过，clean receipt 与精确 CI artifact 一致。
- [ ] 项目简介和 AI/模型披露与最终 AgentTeams 严格凭据逐项一致；凭据无效时删除所有成功 live 表述。
- [ ] 公开仓库 HEAD 与 release ZIP 内公开 CI receipt 一致，v0.2.0 release 和对应 CI artifact 可访问。
- [ ] 最终 MP4 无音轨且字幕可独立说清问题、机制、数字、边界和复现入口。
- [ ] ZIP、PDF、视频、简介、模型与成本披露数值一致。
- [ ] ZIP 未包含本机路径、凭据、完整 GitHub 用户/API payload 或私有数据。
- [ ] 若有 AI Disclosure、登录/实名/协议新字段，停下核对，不推断答案。
