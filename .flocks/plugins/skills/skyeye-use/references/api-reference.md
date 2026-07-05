# SkyEye API 调用指南

SkyEye 当前优先使用 `skyeye_api` provider。

## 先看这张路由表

| 用户意图 | 推荐 tool | 最小参数 |
|---|---|---|
| 查告警列表 | `skyeye_alarm_list` | 可空参，常见补 `start_time`、`end_time` |
| 查告警枚举、攻击阶段、攻击组织、资产组 | `skyeye_alarm_params` | 通常只需要 `data_source` |
| 查看板、趋势、系统状态 | `skyeye_dashboard_view` | 可空参，或给 `name` + `interval_time` |
| 下载告警报告 | `skyeye_download_alarm_report` | `alarm_id`、`export_type`、`start_time`、`end_time` |
| 下载 PCAP | `skyeye_download_pcap` | `alarm_id`、`start_time`、`end_time` |
| 下载告警关联样本 | `skyeye_download_uploadfile` | `alarm_id`、`start_time`、`end_time` |

## 时间参数规则

SkyEye 的 API tool 使用毫秒级时间戳：

- `start_time`
- `end_time`

示例：

```json
{
  "start_time": 1741536000000,
  "end_time": 1741622400000
}
```

如果不传：

- `skyeye_alarm_list` 默认最近 7 天
- `skyeye_dashboard_view` 默认按 `interval_time` 计算
- 下载类接口通常不要省略时间范围，应尽量传告警发生当天窗口

## 1. 告警列表：`skyeye_alarm_list`

### 适合什么

- 获取最近告警列表
- 按威胁级别、状态、数据来源、威胁名称、攻击结果过滤
- 按告警类型、攻击阶段、资产组、攻击维度、IOC、资产 IP 等过滤
- 人工查看分页结果

如果需要对照页面中文字段与接口参数映射，查看 [alarm-reference.md](alarm-reference.md)。

### 最小可运行示例

```json
{}
```

这会使用默认时间范围和默认分页。

### 高频示例

最近 24 小时高危告警：

```json
{
  "start_time": 1741536000000,
  "end_time": 1741622400000,
  "hazard_level": "2,3",
  "offset": 1,
  "limit": 20
}
```

查攻击成功告警：

```json
{
  "host_state": "1",
  "offset": 1,
  "limit": 20
}
```

查某个威胁名称：

```json
{
  "threat_name": "暴力破解",
  "offset": 1,
  "limit": 20
}
```

按攻击阶段和资产组筛选：

```json
{
  "attack_stage": "lateral_movement",
  "asset_group": "1001",
  "offset": 1,
  "limit": 20
}
```

### 参数说明

- `hazard_level`
  - 0=低危
  - 1=中危
  - 2=高危
  - 3=危急
- `threat_type`
  - 告警类型，建议先用 `skyeye_alarm_params` 获取可选值
- `status`
  - 0=未处置
  - 1=已处置
  - 6=忽略
  - 7=误报
- `data_source`
  - 0=全部
  - 1=传感器
  - 2=沙箱
  - 3=邮件沙箱
  - 4=云锁
  - 6=smac
  - 7=蜜罐
  - 8=soar
- `host_state`
  - -1=失败
  - 0=企图
  - 1=成功
  - 2=失陷
- `attack_stage`
  - 攻击阶段，建议先从枚举接口的 `attack_chain` 获取
- `asset_group`
  - 资产组 ID，建议先从枚举接口获取
- `order_by`
  - 排序字段，如 `time`、`hazard_level`
- `offset`
  - 页号，从 1 开始

### 返回结果重点关注

- 告警总数
- 威胁名称
- 威胁级别
- 处理状态
- 数据来源
- 受害 / 攻击 IP
- 攻击结果

### 常见错误

- 时间戳误传成秒
- `offset` 错按 0 开始
- 枚举值传成页面中文，而接口期望数字编码

## 2. 告警枚举值：`skyeye_alarm_params`

### 适合什么

- 获取攻击阶段、攻击组织、资产组、告警类型等筛选参数
- 在调用 `skyeye_alarm_list` 前先探测值域

### 最小示例

```json
{}
```

指定数据源示例：

```json
{
  "data_source": 1
}
```

### 返回结果重点关注

- 攻击阶段
- 威胁组织
- 资产组
- 资产标签
- 告警分类与类型
- 重点关注标签

### 典型使用方式

先查枚举：

```json
{
  "data_source": 1
}
```

再把拿到的枚举值用于 `skyeye_alarm_list` 的筛选参数。

## 3. 看板与趋势：`skyeye_dashboard_view`

### 适合什么

- 整体视图
- 告警级别趋势
- 系统状态
- 看板类分页视图

### 高频 `name`

- `overall_view`
- `alarm_level_trend`
- `alarm_type_trend`
- `alarm_level_pie`
- `alarm_type_pie`
- `apt_hit_rank`
- `alarm_attack_stage`
- `asset_situation_overview`
- `victim_asset_trend`
- `top_attacksrc`
- `system_status`
- `cluster_state`
- `device_info`
- `log_count`
- `server_info`

### 最小示例

```json
{
  "name": "overall_view"
}
```

趋势示例：

```json
{
  "name": "alarm_level_trend",
  "interval_time": 7
}
```

指定绝对时间范围的示例：

```json
{
  "name": "system_status",
  "start_time": 1741536000000,
  "end_time": 1741622400000
}
```

### 返回结果重点关注

- 趋势序列
- 统计数字
- 系统状态汇总
- TOP 列表或分页列表

## 4. 下载告警报告：`skyeye_download_alarm_report`

### 适合什么

- 导出单条告警的详情报告
- 需要 docx 或 pdf 归档材料

### 最小示例

```json
{
  "alarm_id": "alarm-123",
  "export_type": "pdf",
  "start_time": 1741536000000,
  "end_time": 1741622400000
}
```

### 可选参数

- `asset_group`
- `is_white`

### 使用提醒

- `start_time`、`end_time` 最好使用告警发生当天窗口
- 返回结果通常包含文件内容的 base64、文件名、Content-Type

## 5. 下载 PCAP：`skyeye_download_pcap`

### 适合什么

- 获取单条告警关联的抓包文件
- 后续离线分析流量

### 最小示例

```json
{
  "alarm_id": "alarm-123",
  "start_time": 1741536000000,
  "end_time": 1741622400000
}
```

### 常用补充参数

- `alarm_sip`
- `attack_sip`
- `skyeye_type`
- `ioc`
- `type`
- `branch_id`
- `xff`
- `host_state`

## 6. 下载上传文件：`skyeye_download_uploadfile`

### 适合什么

- 获取告警关联的可疑样本
- 对上传文件类告警做后续取证

### 最小示例

```json
{
  "alarm_id": "alarm-123",
  "start_time": 1741536000000,
  "end_time": 1741622400000
}
```

### 常用补充参数

- `alarm_sip`
- `attack_sip`
- `skyeye_type`
- `ioc`
- `host_state`
- `sip_ioc_dip`
- `branch_id`
- `xff`

## 高风险与低风险

查询类 tool 风险较低，下载类 tool 则要更谨慎。

但以下情况仍要谨慎：

- 若用户只是要统计，不要默认拉取很大分页结果
- 若返回结果过大，优先缩小时间范围或分页
- 下载报告、PCAP、样本会产生真实文件内容，不要在未确认需求时主动执行

页面日志检索字段、查询表达式和浏览器日志检索辅助参考见 [log-search-instruction.md](log-searchinstruction.md)。
