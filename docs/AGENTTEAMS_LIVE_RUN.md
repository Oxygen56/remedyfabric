# AgentTeams v1.2.2 live evidence boundary

## 判定规则

官方 AgentTeams 成功闭环不是由本文、容器列表或截图决定。只有
`artifacts/agentteams-live-evidence.json` **存在且通过仓库严格验证器**时，
下述“最终 live 结果”才成立；文件缺失或任一校验失败时，项目只保留历史
`artifacts/agentteams-runtime-blocked.json` 作为失败诊断，不声称成功闭环。

## 最终 live 结果（严格凭据有效时）

严格凭据绑定以下事实：

- 官方上游固定为 `agentscope-ai/AgentTeams` v1.2.2（commit
  `849182af8e017168a5a200a87b1062142caf462d`），并实际运行官方 Controller、
  Manager 与八个 Worker 容器：lead、两个 proposer、两个 Verifier、Challenger、
  Governor、Release Manager；
- Matrix 事件链是 **adapter-assisted、operator-captured** 的类型化协议记录；
  Manager 负责触发与最终 relay，八个 Worker 以各自官方运行时身份参与；
- 两个 proposer 在各自 Worker 容器内真实执行 `remedyfabric-recovery` Skill，
  产生可重建的 `PatchCandidate` 与 `CandidateProposal`；
- 两个 Verifier 分别执行可见测试与不变量，lead 执行收敛复核，Challenger
  执行负向检查，Governor 执行策略检查，Release Manager 真实调用
  `QuorumGate`；每次执行与输入收据、输出收据、run/snapshot/candidate 上下文
  和 Matrix 事件相互绑定；
- 本地 Ollama `gpt-oss:20b` 的模型摘要为
  `17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7`，
  参数量 20.9B、量化 MXFP4、许可证 Apache-2.0；模型/API 费用 USD 0.00，
  使用本地算力且不调用商业模型 API；
- 官方 Alibaba Cloud `alibabacloud-resourcecenter-search` Skill 固定到公开包并
  完成包校验；本次仅由 adapter 执行无凭据预检，在任何云请求前以
  `missing_credentials` 退出，没有读取云凭据、没有查询云资源、没有云 API
  成本，也不将此描述成一次云端运行；以及
- 运行时拒绝路径、容器/镜像身份、脱敏 Matrix 原始事件和最终 Manager relay
  均包含在同一随机 nonce 与捕获时间窗中。

这个结果证明的是“官方运行组件中的真实角色执行与可复核协议闭环”。它**不**
声称 LLM 自主规划并编排了整个任务，也不声称角色拥有独立模型、独立实现、独立
机器或独立故障域。核心安全数字仍来自无需模型、账号或网络的确定性执行路径。

## 历史失败与 supersede 规则

`artifacts/agentteams-runtime-blocked.json` 记录了较早的真实失败：官方组件曾启动，
一次越权访问得到 HTTP 403，但当时模型路由失败且没有完成 Manager→Worker→Manager
链路。该凭据永远不能单独证明成功。

若最终 `agentteams-live-evidence.json` 存在且严格有效，它会以更新的 nonce、时间窗、
源代码摘要、完整八 Worker 拓扑、类型化事件 DAG 和真实工具收据 **supersede** 这次
历史失败，仅针对“最终成功闭环是否成立”的判定；历史失败记录本身仍保留以展示
迭代过程。若最终凭据缺失或失效，supersede 不发生，成功 live 证据仍为未满足。

## 隐私与复现边界

原始令牌、网关密钥、Matrix 凭据、私有环境变量和未经脱敏的运行日志不得写入公开
仓库。公开凭据只保留验证所需的最小身份、请求/响应、哈希、容器导出和事件字段。
连接探针、容器处于 Running、模型 HTTP 200、manifest 或角色名称都不能替代严格
闭环凭据。
