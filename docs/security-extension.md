# Security Extension MVP

## 1. 产品定位

Security Extension 将 Flocks 扩展为“AI 驻场安全专家平台”的 MVP 原型，面向资产风险分析、漏洞优先级、告警研判、安全事件生成和客户可读报告输出。

第一阶段不是 SIEM、SOAR、漏洞扫描器或蜜罐内核，而是一个可演示的安全运营闭环：

资产 / 漏洞 / 告警 / 诱捕事件导入和查询 → Agent 调用 Security Tools 关联分析 → 自动或手动生成 Incident → 输出处置建议 → 生成 Markdown 事件报告 → WebUI 查看和操作。

## 2. 架构说明

新增能力以扩展层形式接入：

- 后端业务层：`flocks/security/`
- API 路由：`flocks/server/routes/security.py`
- Agent 可调用工具：`flocks/tool/security/security_ops.py`
- WebUI：`webui/src/pages/Security/`
- 项目级 Agent / Skill / Workflow：`.flocks/plugins/...`

该扩展复用现有 Storage、ToolRegistry、Agent、Skill、Workflow 和 WebUI 路由机制，不替换 Flocks Core。

## 3. 新增目录说明

- `flocks/security/models.py`：资产、漏洞、告警、事件、诱捕事件和研判结果模型。
- `flocks/security/schemas.py`：API 与 Store 的 create/update/filter schema。
- `flocks/security/store.py`：基于 Storage KV 的 CRUD 和过滤。
- `flocks/security/scoring.py`：轻量风险评分。
- `flocks/security/profile.py`：资产风险画像聚合与证据/不确定性输出。
- `flocks/security/prioritization.py`：漏洞优先级排序。
- `flocks/security/connectors/`：连接器 Manifest、能力声明、字段标准化、Mock Connector 和 Fixture Replay。
- `flocks/security/correlation.py`：告警关联分析。
- `flocks/security/triage.py`：告警研判和 Incident 幂等创建。
- `flocks/security/report.py`：Markdown 事件报告生成。
- `flocks/security/sample_data.py`：演示样例数据加载和精准清理。

## 4. 数据模型

MVP 支持五类对象：

- Asset：资产台账，包含类型、IP、域名、业务系统、重要性、暴露面、环境、开放端口、服务、防护接入和标签。
- Vulnerability：漏洞或风险，包含 CVE、severity、CVSS、EPSS、KEV、exploit_available、修复建议和状态。
- Alert：安全告警，包含来源、严重等级、IOC、MITRE Technique、原始事件摘要和状态。
- Incident：安全事件，关联资产、漏洞、告警，包含分析、建议、置信度和状态。
- HoneypotEvent：诱捕事件预留模型，用于关联分析，不包含蜜罐内核。

Storage key prefix：

- `security/assets/`
- `security/vulnerabilities/`
- `security/alerts/`
- `security/incidents/`
- `security/honeypot-events/`
- `security/sample-data/manifest`

所有核心对象保留 `raw_data`，并输出 `normalized_data`，用于连接器适配层保留厂商原始响应并暴露统一安全对象字段。Alert 继续兼容既有 `raw_event` 字段。

## 5. API 清单

- `GET /api/security/health`
- `GET /api/security/connectors`
- `GET /api/security/connectors/{connector_id}`
- `GET /api/security/connectors/{connector_id}/capabilities`
- `POST /api/security/connectors/{connector_id}/preview?capability=asset.search`
- `POST /api/security/connectors/{connector_id}/test`
- `GET|POST /api/security/assets`
- `GET|PATCH|DELETE /api/security/assets/{asset_id}`
- `GET /api/security/assets/{asset_id}/risk-profile`
- `GET|POST /api/security/vulnerabilities`
- `GET /api/security/vulnerabilities/prioritized`
- `GET|PATCH|DELETE /api/security/vulnerabilities/{vuln_id}`
- `GET|POST /api/security/alerts`
- `GET|PATCH|DELETE /api/security/alerts/{alert_id}`
- `GET|POST /api/security/incidents`
- `GET|PATCH|DELETE /api/security/incidents/{incident_id}`
- `GET|POST /api/security/honeypot-events`
- `GET|PATCH|DELETE /api/security/honeypot-events/{event_id}`
- `POST /api/security/triage/alert/{alert_id}`
- `POST /api/security/correlate/alert/{alert_id}`
- `POST /api/security/incidents/from-alert/{alert_id}`
- `POST /api/security/reports/incident/{incident_id}`
- `POST /api/security/sample-data/load`
- `DELETE /api/security/sample-data/clear`

列表接口支持 `asset_id`、`severity`、`status`、`source`、`keyword`、`ip`、`domain`、`hostname`、`ioc`、`mitre_technique`、`limit` 等过滤参数。

## 6. Tool 清单

Agent 可调用以下工具：

- `security_asset_search`
- `security_asset_get`
- `security_asset_risk_profile`
- `security_connector_list`
- `security_connector_get`
- `security_connector_test_connection`
- `security_connector_list_capabilities`
- `security_connector_preview`
- `security_vulnerability_search`
- `security_vulnerability_prioritize`
- `security_alert_search`
- `security_alert_get`
- `security_alert_triage`
- `security_correlate_alert`
- `security_incident_create`
- `security_incident_get`
- `security_report_generate`
- `security_honeypot_event_search`

这些工具只查询、研判、创建事件记录和生成报告，不执行真实处置动作。

## 7. Agent 清单

新增项目级 Agent：

- `resident-security-expert`：AI 驻场安全专家，主 Agent。
- `asset-risk-analyst`：资产风险分析专家。
- `alert-triage-analyst`：告警研判专家。
- `incident-report-writer`：安全事件报告专家。

Agent 默认绑定 `security_*` 工具和安全 SOP Skill，不绑定真实封禁、隔离、删除或漏洞利用能力。

## 8. Workflow 清单

新增项目级 Workflow：

- `alert_triage_workflow`
- `asset_risk_profile_workflow`
- `vulnerability_prioritization_workflow`
- `incident_report_workflow`

Workflow 通过 `tool.run_safe("security_*", ...)` 调用安全工具。

## 9. WebUI 使用方法

启动 WebUI 后访问：

- `/security`：Dashboard
- `/security/assets`：资产中心
- `/security/vulnerabilities`：漏洞中心
- `/security/alerts`：告警中心
- `/security/incidents`：事件中心
- `/security/honeypot-events`：诱捕事件
- `/security-admin/connectors`：连接器 Manifest、能力声明、测试连接、Fixture Preview 和 raw/normalized 示例预览

Dashboard 可加载和清理样例数据。列表页支持基础搜索、新增、编辑、删除、查看详情。Alert Center 可触发 AI 研判和从告警创建 Incident。Incident Center 可生成 Markdown 报告。Security Admin 的 Connector 页面可查看 Mock Connector 和 Fixture Replay Connector 的能力声明、测试结果、预览结果、缺失字段 warnings 与标准化输出。

## 10. 样例数据演示流程

1. 打开 `/security`。
2. 点击 `Load Sample`。
3. 在 Asset Center 查看 `Internet Portal`。
4. 在 Vulnerability Center 查看 `CVE-DEMO-2026-0001`。
5. 在 Alert Center 对“疑似 WebShell 上传或异常命令执行”点击 AI 研判。
6. 系统根据外网关键资产、高危漏洞、XDR 告警和诱捕命中自动生成或复用 Incident。
7. 在 Incident Center 点击报告按钮生成 Markdown 安全事件研判报告。
8. 在 Asset Center 点击资产行操作中的风险画像按钮，查看资产画像、证据、推断和不确定点。
9. 点击 `Clear Sample` 只清理样例对象和由样例告警生成的样例 Incident。

## 11. 当前限制

- 不存储海量原始日志。
- 不对接真实安全设备 API。
- 不实现漏洞扫描、攻击验证、蜜罐 Sensor 或自动化处置。
- 不提供多租户隔离和细粒度权限。
- 风险评分为 MVP 规则模型，不等价于完整风险量化体系。

## 12. 后续路线图

- 增加资产导入和批量同步。
- 对接 XDR/EDR/NDR/WAF/SIEM/漏洞管理平台。
- 将 Mock Connector 扩展为真实厂商 Adapter，并按 Capability 做工作流降级。
- 增加事件时间线和证据链视图。
- 增加审批型 SOAR 动作，但默认仍需人工确认。
- 引入多租户、权限分层和客户视图。
- 将风险评分升级为可配置策略和可解释评分模型。
