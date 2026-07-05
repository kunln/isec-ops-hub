# SkyEye 日志搜索参考

> 这里保留旧 skill 中最关键的日志字段知识，供 `skyeye-use` 在浏览器回退或后续补充日志 API 时使用。

## 当前定位

`skyeye-use` 默认优先使用现有 `skyeye_api` provider，不直接走旧 CLI。

但如果用户在页面里进行日志检索、需要理解 SkyEye 常见日志字段或为后续浏览器操作做字段对照，可参考本文。

## 高频字段

| 页面中文字段 | 字段名 | 示例 |
| --- | --- | --- |
| 日志时间 | `@timestamp` | `@timestamp:(2026-03*)` |
| 主机名 | `host_name` | `host_name:(server-01)` |
| 资产IP | `asset_ip` | `asset_ip:(10.0.0.8)` |
| 源IP | `sip` | `sip:(1.1.1.1)` |
| 目的IP | `dip` | `dip:(2.2.2.2)` |
| 域名 | `domain` | `domain:(example.com)` |
| URI | `uri` | `uri:(/login)` |
| 协议 | `proto` | `proto:(http)` |
| 威胁名称 | `threat_name` | `threat_name:(木马)` |
| 受害IP | `alarm_sip` | `alarm_sip:(10.0.0.1)` |
| 攻击IP | `attack_sip` | `attack_sip:(1.1.1.1)` |
| 危险等级 | `hazard_level` / `hazard_rating` | `hazard_level:(8)` |
| 攻击结果 | `attack_result` | `attack_result:(攻击成功)` |
| 处理状态 | `status` | `status:(已处置)` |

## 查询表达式风格

常见写法：

```text
field:(value)
```

组合示例：

```text
alarm_sip:(10.0.0.1)
host_name:(server-01) AND threat_name:(木马)
sip:(1.1.1.1) AND dport:(443)
uri:(/api/*)
```

## 典型使用场景

- 浏览器页面日志检索时，需要把中文条件翻译成英文字段
- 页面能查到、API 还没暴露日志接口时，用这些字段辅助页面查询
- 后续若新增日志 API，可直接复用这些字段说明

## 排障建议

- 页面能查到但 API 没有对应参数时，优先回退浏览器
- 字段名不确定时，先从这里找英文名
- 时间范围、数据源、页面默认筛选经常导致“页面有数据、接口没数据”的错觉
