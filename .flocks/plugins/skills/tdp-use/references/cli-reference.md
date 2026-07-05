# TDP CLI 参考

本文档覆盖 TDP 精简版 CLI 的两个接口：威胁事件查询和告警日志搜索。

---

## 接口一：威胁事件查询

**POST** `api/web/hw/monitor/threat/list`

查询**聚合后的威胁事件**列表。一条记录 = 一个威胁事件，包含该事件的检出次数、攻击者、受害主机等汇总信息。对应 TDP 页面：`/threatMonitor`（实时监控）。

### 调用方式

```bash
THREATBOOK_BASE_URL=https://<tdp-domain> \
THREATBOOK_COOKIE_FILE=~/.flocks/browser/tdp/auth-state.json \
python .flocks/plugins/skills/tdp-use/scripts/tdp_cli.py \
  monitor threats [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `--sql` | `-s` | `(threat.level IN ('attack')) AND threat.type NOT IN ('recon')` | SQL 过滤条件 |
| `--days` | `-d` | `1` | 查询最近 N 天 |
| `--hours` | `-H` | — | 查询最近 N 小时（**优先于 `--days`**） |
| `--from` | — | — | 开始时间（优先级最高）：时间戳 / 日期 / 日期+时间 |
| `--to` | — | 当前时间 | 结束时间 |
| `--limit` | `-l` | `20` | 显示条数（等同于 `--page-size`，**优先于 `--page-size`**） |
| `--page` | `-p` | `1` | 页码 |
| `--page-size` | `-n` | `20` | 每页条数 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 请求体结构

```json
{
  "condition": {
    "time_from": 1741536000,
    "time_to": 1741622400,
    "refresh_rate": -1,
    "sql": "(threat.level IN ('attack'))",
    "columns": [
      {"label": "最近发现时间", "value": "time"},
      {"label": "类型", "value": ["threat.level", "threat.result"]},
      {"label": "攻击者IP/IOC", "value": "attacker"},
      {"label": "威胁名称", "value": "threat.name"},
      {"label": "威胁方向", "value": "direction"},
      {"label": "源IP", "value": "net.src_ip"},
      {"label": "目的IP", "value": "net.dest_ip"},
      {"label": "严重级别", "value": "threat.severity"},
      {"label": "检出次数", "value": "alert_count"}
    ]
  },
  "page": {
    "cur_page": 1,
    "page_size": 20,
    "sort": [{"sort_by": "time", "sort_order": "desc"}]
  }
}
```

### 排序字段

`sort_by` 支持：`time`（最近发现时间）、`alert_count`（检出次数）

### SQL 过滤字段

与告警日志查询使用相同 SQL 语法，但语义是**事件维度**（已聚合），常用字段：

| 字段 | 说明 | 枚举值 |
|------|------|--------|
| `threat.level` | 行为类型 | `attack` / `action` / `risk` |
| `threat.result` | 攻击结果 | `success` / `failed` / `unknown` |
| `threat.severity` | 严重级别 | `0`信息 / `1`低 / `2`中 / `3`高 / `4`严重 |
| `threat.type` | 威胁类型 | `exploit` `shell` `c2` `trojan` `ransom` `mining` `botnet` `recon` 等 |
| `threat.name` | 威胁名称 | string，支持 LIKE |
| `direction` | 威胁方向 | `in` 外部攻击 / `out` 失陷破坏 / `lateral` 内网渗透 |
| `attacker` | 攻击者 IP | string |
| `victim` | 受害者 IP | string |
| `machine` | 告警主机 IP | string |
| `is_hw_ip` | HW IP | `1` / `0` |
| `hw_ip_level` | HW IP 可信度 | `1` 高可信 / `2` 已确认 |
| `threat.is_apt` | 是否 APT | `1` / `0` |

### 查询示例

```bash
# 默认：最近1天的攻击事件
monitor threats

# 最近6小时 + 攻击成功，前100条
monitor threats --hours 6 --sql "threat.level = 'attack' AND threat.result = 'success'" --limit 100

# 最近3天 + 高危及以上
monitor threats --days 3 --sql "threat.severity IN ('3', '4')"

# 漏洞利用事件（外部攻击方向）
monitor threats --sql "threat.type = 'exploit' AND direction = 'in'"

# C2 / 失陷破坏
monitor threats --sql "threat.type = 'c2' OR direction = 'out'"

# 内网渗透
monitor threats --sql "direction = 'lateral'"

# 切换为表格输出
monitor threats --table-output

# 翻页（第2页，每页50条）
monitor threats --page 2 --page-size 50
```

---

## 接口二：告警日志搜索

**POST** `api/web/log/searchBySql`

查询**原始告警日志**。一条记录 = 一条独立的告警检测记录，包含完整的网络会话信息（源/目的 IP、端口、协议、URL）。对应 TDP 页面：`/investigation/logquery`（日志分析）。

### 调用方式

```bash
THREATBOOK_BASE_URL=https://<tdp-domain> \
THREATBOOK_COOKIE_FILE=~/.flocks/browser/tdp/auth-state.json \
python .flocks/plugins/skills/tdp-use/scripts/tdp_cli.py \
  logs search [--sql "<SQL条件>"] [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `[SQL]` | — | `""` | SQL 过滤条件（位置参数，与 `--sql` 等效） |
| `--sql` | `-s` | — | SQL 过滤条件（**优先于位置参数**） |
| `--days` | `-d` | `1` | 查询最近 N 天 |
| `--hours` | `-H` | — | 查询最近 N 小时（**优先于 `--days`**） |
| `--from` | — | — | 开始时间（优先级最高）：时间戳 / 日期 / 日期+时间 |
| `--to` | — | 当前时间 | 结束时间 |
| `--limit` | `-l` | `20` | 显示条数限制 |
| `--net-data-type` | `-t` | `attack risk action` | 流量类型，可多次指定 |
| `--full` | `-f` | — | **全字段模式**：不传 `columns`，后端返回全部字段（含原始载荷、HTTP 报文等）。**仅在明确需要完整字段，或按 `threat.id` 查看单条告警详情时使用** |
| `--columns` | `-c` | — | 自定义返回字段，逗号分隔（优先级高于 `--full`），如 `threat.name,net.http.url,threat.msg` |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

> **字段模式优先级**：`--columns` > `--full`（全字段）> 默认（页面展示字段）
>
> **使用原则**：默认模式适合绝大多数批量筛查和统计分析；只有在用户明确要求完整字段，或你已经拿到具体 `threat.id` 要拉取单条告警详情时，才启用 `--full`

### 请求体结构

**默认模式**（与页面展示字段一致）：

```json
{
  "time_from": 1741536000,
  "time_to": 1741622400,
  "sql": "threat.level = 'attack'",
  "assets_group": [],
  "net_data_type": ["attack", "risk", "action"],
  "columns": [
    {"label": "类型", "value": ["threat.level", "threat.result"]},
    {"label": "日期", "value": "time"},
    ...
  ]
}
```

**全字段模式**（`--full`，不传 columns，后端返回全部字段）：

```json
{
  "time_from": 1741536000,
  "time_to": 1741622400,
  "sql": "threat.id='xxx'",
  "assets_group": [],
  "net_data_type": ["attack", "risk", "action"]
}
```

### net_data_type 说明

| 值 | 含义 |
|----|------|
| `attack` | 攻击类告警 |
| `risk` | 风险类告警 |
| `action` | 敏感行为告警 |

### SQL 字段速查

#### 威胁相关

| 字段 | 说明 | 枚举值 / 类型 |
|------|------|--------------|
| `threat.level` | 行为类型 | `attack` / `action` / `risk` |
| `threat.result` | 攻击结果 | `success` / `failed` / `unknown` |
| `threat.severity` | 严重级别 | `0`信息 / `1`低 / `2`中 / `3`高 / `4`严重 |
| `threat.type` | 威胁类型 | `exploit` `shell` `c2` `trojan` `ransom` `mining` `botnet` `recon` `dga` `phishing` 等 |
| `threat.phase` | 攻击阶段 | `recon` / `exploit` / `control` / `attack_out` / `post_exploit` |
| `threat.name` | 威胁名称 | string，支持 LIKE |
| `threat.characters` | 威胁性质 | `is_compromised` / `is_connected` / `is_apt` / `is_lateral` / `is_in_success` |
| `threat.is_connected` | 是否连通 | `1` / `0` |
| `threat.is_apt` | 是否 APT | `1` / `0` |
| `threat.is_0day` | 是否 0day | `1` / `0` |
| `threat.msg` | 威胁信息 | string，支持 LIKE |
| `threat.suuid` | 情报/规则/模型 ID | string |
| `incident_id` | 所属威胁事件 ID | string |

> 数值字段（端口、流量、严重级别数字比较）不加引号；枚举/字符串字段加单引号。

> 完整 60+ 字段列表（含 DNS、FTP、SMTP、Kerberos、LDAP、ATT&CK 等协议专属字段及全部枚举值）见 [instruction.md](instruction.md)。


### 查询示例

```sql
-- 查询攻击成功告警
threat.level = 'attack' AND threat.result = 'success'

-- 特定主机的所有告警
machine = '192.168.1.100'

-- 高危及以上（严重级别 3/4）
threat.severity IN ('3', '4')

-- 漏洞利用（外部攻击成功）
threat.type = 'exploit' AND direction = 'in' AND threat.result = 'success'

-- Webshell / 后门
threat.type = 'shell'

-- C2 已连通
threat.type = 'c2' AND threat.is_connected = '1'

-- 失陷主机（对外连通）
threat.characters = 'is_compromised'

-- 内网横向渗透成功
direction = 'lateral' AND threat.result = 'success'

-- 境外 IP 攻击
geo_data.Country NOT IN ('中国') AND direction = 'in' AND threat.level = 'attack'

-- 大流量外传（可能数据外泄）
direction = 'out' AND net.bytes_toclient > 10000000

-- 数据库协议攻击
net.app_proto IN ('mysql', 'postgresql', 'redis', 'oracle') AND threat.level = 'attack'

-- DNS 隧道
net.dns.rrtype IN ('TXT', 'NULL') AND threat.level = 'attack'

-- 特定 URL 路径
net.http.url LIKE '%/admin/%' AND threat.level = 'attack'

-- APT / 0day
threat.is_apt = '1'
threat.is_0day = '1'

-- HW 护网：高可信攻击 IP
is_hw_ip = '1' AND hw_ip_level = '2'

-- 查特定威胁事件关联的所有原始告警
incident_id = 'ebc8d286b73f4c617808f32850dcb75c-1653997925'
```

### CLI 调用示例

```bash
# 基础查询（默认字段，最近1天）
logs search

# 攻击成功告警，最近6小时
logs search --sql "threat.level = 'attack' AND threat.result = 'success'" --hours 6

# 查指定 threat.id 的完整详情（此类场景才建议启用全字段模式）
logs search --sql "threat.id='d6og8q3213mdim55oamg'" --full

# 自定义字段：只取威胁名称 + HTTP URL + 请求体
logs search --sql "machine='192.168.1.100'" --columns "threat.name,net.http.url,net.http.reqs_body"

# 翻查历史（指定时间段）
logs search --from "2026-03-10 09:00" --to "2026-03-10 17:00" --limit 100

# 切换为表格输出
logs search --limit 5 --table-output
```

---

## 两个接口对比

| | 威胁事件查询 (`monitor threats`) | 告警日志搜索 (`logs search`) |
|---|---|---|
| **数据维度** | 威胁**事件**（已聚合） | 原始**告警**（未聚合） |
| **一条记录** | 一个威胁事件，含 N 条告警 | 一条独立告警检测记录 |
| **主要字段** | 威胁名称、攻击者、检出次数、方向 | 源/目的 IP+端口、协议、URL、HTTP 详情 |
| **SQL 引擎** | 相同 SQL 语法 | 相同 SQL 语法 |
| **何时使用** | 查"发生了哪些威胁事件"、事件总览 | 查"具体每条告警"、分析 URL/payload、按 IP 追踪行为 |
| **浏览器对应页面** | `/threatMonitor` 实时监控 | `/investigation/logquery` 日志分析 |

---

## 何时用 CLI vs 浏览器

| 需求 | 方式 |
|------|------|
| SQL 条件查询威胁事件 | **CLI `monitor threats`（本接口一）** |
| SQL 条件查询告警日志 | **CLI `logs search`（本接口二）** |
| 查看 PCAP / 原始报文 | 浏览器点击详情 |
| 不确定查询条件，交互式探索 | 浏览器 `/investigation/logquery` |
| 跨类型浏览威胁事件 | 浏览器 `/threatMonitor` |
