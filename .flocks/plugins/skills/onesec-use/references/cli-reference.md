# OneSEC CLI 参考

本文档覆盖 OneSEC 精简版 CLI 的 5 个接口：

- `threat search`
- `threat top`
- `log search`
- `log types`
- `log trend`

适用场景：**已经进入浏览器模式**，但查询类需求更适合走本地 CLI 获取稳定结果，而不是直接在页面上点击筛选。

---

## 认证与环境变量

浏览器模式下的 CLI 默认复用 OneSEC 浏览器 state，也支持 cookie 和 token：

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py --help
```

支持的认证来源：

- `ONESEC_AUTH_STATE`：浏览器保存的 `auth-state.json`，优先使用
- `ONESEC_COOKIE_FILE`：导出的 cookie JSON 文件
- `ONESEC_CSRF_TOKEN`：备用 token
- `ONESEC_BASE_URL`：OneSEC 域名，默认 `https://console.onesec.net`

说明：

- 若 `ONESEC_AUTH_STATE` 对应文件存在，会优先从其中提取 cookie 和 `csrfToken`
- 若没有 state 文件，则回退到 `ONESEC_COOKIE_FILE`
- 若两者都没有，则使用 `ONESEC_CSRF_TOKEN`

---

## 接口一：威胁行动搜索

**POST** `api/saasedr/threat/action/search`

按时间窗口查询威胁行动列表，支持分页和关键词搜索。对应 OneSEC 页面语义：EDR 威胁事件 / 威胁行动相关列表。

### 调用方式

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py \
  threat search [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `--days` | `-d` | `7` | 查询最近 N 天 |
| `--page` | `-p` | `1` | 页码 |
| `--page-size` | `-s` | `20` | 每页数量 |
| `--keyword` | `-k` | `""` | 关键词搜索 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 请求体要点

```json
{
  "time_from": 1741536000,
  "time_to": 1741622400,
  "keyword": "勒索",
  "sorts": [
    {"sort_by": "last_signal_time", "sort_order": "desc"},
    {"sort_by": "threat_severity", "sort_order": "desc"}
  ],
  "page": {
    "cur_page": 1,
    "page_size": 20
  }
}
```

### 返回重点

- `data.items`
- `data.total`
- `items[].host_name`
- `items[].threat_name`
- `items[].threat_severity`
- `items[].last_signal_time`

### 查询示例

```bash
# 最近 7 天威胁行动
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat search

# 最近 3 天，关键字包含 powershell
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat search --days 3 --keyword "powershell"

# 第 2 页，每页 50 条
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat search --page 2 --page-size 50

# 表格输出
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat search --table-output
```

---

## 接口二：TOP 威胁名称

**POST** `api/saasedr/threat/action/name/top`

查看指定时间范围内的 TOP 威胁名称统计。

### 调用方式

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py \
  threat top [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `--days` | `-d` | `7` | 查询最近 N 天 |
| `--limit` | `-l` | `10` | 返回数量 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 返回重点

- `data[].name`
- `data[].count`

### 查询示例

```bash
# 最近 7 天 TOP 威胁
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat top

# 最近 1 天，前 20 个威胁名称
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py threat top --days 1 --limit 20
```

---

## 接口三：SQL 日志搜索

**POST** `api/saasedr/log/searchBySql`

按 SQL 检索 OneSEC 日志。对应 OneSEC 页面：`/pcedr/investigation`。

### 调用方式

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py \
  log search "<SQL条件>" [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `SQL` | — | 必填 | SQL 查询条件，位置参数 |
| `--days` | `-d` | `1` | 查询最近 N 天 |
| `--hours` | `-H` | — | 查询最近 N 小时，优先于 `--days` |
| `--limit` | `-l` | `10` | 表格模式下显示前 N 条 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 请求体要点

```json
{
  "time_from": 1741536000,
  "time_to": 1741622400,
  "sql": "threat.level = 'attack'",
  "useLoggingTime": true,
  "page": {
    "cur_page": 1,
    "page_size": 50
  },
  "sort": [
    {"sort_by": "event_time", "sort_order": "desc"}
  ]
}
```

> CLI 内部会使用 `page_size=max(limit, 50)` 请求后端，但表格模式只展示前 `limit` 条。

### 返回重点

- `data.tbBaseLogList`
- `data.total`
- `tbBaseLogList[].event_time`
- `tbBaseLogList[].host_name`
- `tbBaseLogList[].threat.name`
- `tbBaseLogList[].event_name`

### 查询示例

```bash
# 最近 1 天攻击类日志
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log search "threat.level = 'attack'"

# 最近 6 小时高危日志
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log search "threat.severity >= 3" --hours 6 --limit 20

# 查询某台主机最近日志
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log search "host_name = 'server01'" --days 3

# 表格输出
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log search "threat.level = 'attack'" --table-output
```

---

## 接口四：日志类型统计

**POST** `api/saasedr/log/type-count`

查看指定时间范围内的日志类型统计。

### 调用方式

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py \
  log types [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `--days` | `-d` | `1` | 查询最近 N 天 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 返回重点

- `data` 为字典，键是日志类型，值是数量

### 查询示例

```bash
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log types
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log types --days 7 --table-output
```

---

## 接口五：日志趋势

**POST** `api/saasedr/log/trend`

查看指定时间范围内的日志趋势统计。

### 调用方式

```bash
ONESEC_BASE_URL=https://<onesec-domain> \
ONESEC_AUTH_STATE=~/.flocks/browser/onesec/auth-state.json \
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py \
  log trend [选项]
```

### 参数

| 参数 | 短参 | 默认值 | 说明 |
|------|------|--------|------|
| `--days` | `-d` | `1` | 查询最近 N 天 |
| `--json-output` | `-j` | `开启` | 默认输出原始 JSON |
| `--table-output` | — | `关闭` | 切换为 Rich 表格输出 |

### 返回重点

- `data.trend[].time`
- `data.trend[].count`

### 查询示例

```bash
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log trend
python .flocks/plugins/skills/onesec-use/scripts/onesec_cli.py log trend --days 3 --table-output
```

---

## 何时优先用 CLI

下列场景优先使用本 CLI，而不是直接页面点击：

- 已进入浏览器模式，但需求本质是查询类统计或列表拉取
- 需要稳定复现同一组查询条件
- 需要按 SQL 检索日志，且无需点击页面详情
- 需要获取结构化 JSON 结果供后续摘要或分析

下列场景再回退页面操作：

- 需要查看事件详情、威胁图、处置弹窗、复杂联动
- 需要人工登录、验证码、多因子认证或页面确认
- 需要使用页面特有的交互式筛选、AI 查询或详情下钻
