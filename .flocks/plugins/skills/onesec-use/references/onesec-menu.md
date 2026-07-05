# OneSEC 控制台完整菜单与 URL 映射

## 一、监控和报告

| 名称 | URL | 描述 |
|------|-----|------|
| 概览 | `/monitor/overview` | 系统整体概览 |
| 终端安全概览 | `/pcedr/dashboard` | 终端安全状态总览 |
| DNS防护概览 | `/onedns/console/dashboard` | DNS安全防护概览 |
| 银狐防治 | `/antisilverfox` | 银狐病毒专项防治 |
| 报告中心 | `/onedns/console/reports` | 各类报表查看中心 |

## 二、终端检测与响应 (EDR)

| 名称 | URL | 描述 |
|------|-----|------|
| 威胁事件 | `/pcedr/threatincidents` | 安全威胁事件管理 |
| 检出行为 | `/pcedr/anomalyactivities` | 异常行为检测 |
| 恶意文件 | `/pcedr/threatfiles` | 恶意文件管理 |
| 日志调查 | `/pcedr/investigation` | 安全日志分析调查 |
| 响应中心 | `/pcedr/tasks` | 安全响应任务中心 |
| 威胁狩猎 | `/pcedr/threat_hunting` | 主动威胁狩猎 |

## 三、DNS安全防护

| 名称 | URL | 描述 |
|------|-----|------|
| 域名解析报表 | `/onedns/console/domains` | 域名解析统计报表 |
| 域名解析日志 | `/onedns/console/domainLog` | DNS查询日志 |
| 安全事件报表 | `/onedns/console/securityincident` | DNS安全事件统计 |
| 内容分类报表 | `/onedns/console/contentCategory` | 网站内容分类统计 |
| 威胁定位处置 | `/onedns/console/threatMitigation` | DNS威胁定位与处置 |
| VA溯源日志 | `/onedns/console/vaInvestigation` | VA溯源调查日志 |

## 四、漏洞补丁管理

| 名称 | URL | 描述 |
|------|-----|------|
| 漏洞管理 | `/vulnerability_manage` | 系统漏洞管理 |
| 补丁管理 | `/patch_manage` | 补丁分发管理 |

## 五、软件安全

| 名称 | URL | 描述 |
|------|-----|------|
| 已安装软件/AI应用 | `/pcedr/softwarelist` | 软件资产清单 |
| 软件管控 | `/software_control` | 软件黑白名单管理 |
| 软件管控日志 | `/pcedr/software_log` | 软件管控操作日志 |

## 六、外设管控

| 名称 | URL | 描述 |
|------|-----|------|
| 外设管控日志 | `/device_control_log` | 外设使用日志 |

## 七、组织架构

| 名称 | URL | 描述 |
|------|-----|------|
| 职场/分组管理 | `/groupmanagement` | 组织架构管理 |

## 八、终端接入管理

| 名称 | URL | 描述 |
|------|-----|------|
| 终端管理 | `/pcedr/agent_group` | 终端设备管理 |
| 终端策略 | `/pcedr/policies` | 终端安全策略配置 |
| 信任名单 | `/pcedr/whitelist` | 信任文件/进程管理 |
| 自定义IOC/IOA | `/pcedr/ioc` | 威胁指标自定义 |
| 终端部署 | `/pcedr/deployment` | Agent部署管理 |

## 九、DNS接入管理

| 名称 | URL | 描述 |
|------|-----|------|
| 网络出口配置 | `/onedns/console/deployNetworkConfig` | DNS出口IP配置 |
| VA部署 | `/onedns/console/sysConfig/vaclientConfig` | VA设备部署管理 |
| DNS防护策略 | `/onedns/console/allPolicies` | DNS安全策略配置 |
| 拦截放行域名 | `/onedns/console/polices/destList` | 域名黑白名单 |

## 十、平台管理

| 名称 | URL | 描述 |
|------|-----|------|
| 开放接口 | `/apiList` | API接口文档 |
| 登录管理 | `/pcedr/users` | 账号权限管理 |
| 通知管理 | `/pcedr/notice` | 消息通知配置 |
| 审计日志 | `/pcedr/audit_log` | 操作审计日志 |
| 平台配置 | `/platformconfig` | 系统参数配置 |
| 敏感数据加密 | `/pcedr/encrypt_data` | 数据加密设置 |
