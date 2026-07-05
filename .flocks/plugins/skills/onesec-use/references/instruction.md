# OneSEC 日志调查字段说明

> 页面：`/pcedr/investigation`

## 操作符说明

| 操作符 | 说明 | 示例 |
| --- | --- | --- |
| `AND` | 与运算 | `threat.level = 'attack' AND host_name = 'server-01'` |
| `OR` | 或运算 | `threat.name = '木马' OR threat.name = '勒索'` |
| `=` | 精确匹配 | `threat.level = 'attack'` |
| `>` / `>=` / `<` / `<=` | 数值比较 | `net.bytes_toserver > 1000` |
| `<>` | 不等于 | `threat.level <> 'risk'` |
| `is null` / `is not null` | 空值判断 | `threat.level is not null` |
| `LIKE` / `NOT LIKE` | 模糊匹配 | `proc.cmdline LIKE '%powershell%'` |
| `IN` / `NOT IN` | 多值匹配 | `host_ip IN ('10.0.0.1', '10.0.0.2')` |

## 常用字段

### 终端基础信息

| 中文名 | JSON 字段 |
|-------|-----------|
| 终端名称 | `host_name` |
| 终端内网IP | `host_ip` |
| 终端MAC地址 | `host_mac` |
| 职场 / 分组 | `group_name` |
| 主机 Mid | `umid` |
| 终端使用人 | `user_name` |
| 事件时间 | `event_time` |

### 威胁信息

| 中文名 | JSON 字段 | 典型值 |
|-------|-----------|-------|
| 事件性质 | `threat.level` | `attack` / `risk` |
| 威胁名称 | `threat.name` | `异常进程链` |
| 严重级别 | `threat.severity` | `1` / `2` / `3` |
| 威胁阶段 | `threat.phase` | 权限获取 / 防御绕过 / 恶意文件 |
| 威胁描述 | `threat.msg` | 文本 |
| 威胁规则ID | `threat.id` | 字符串 |
| 是否 APT | `threat.is_apt` | `0` / `1` |

### 进程信息

| 中文名 | JSON 字段 |
|-------|-----------|
| 进程文件名 | `proc.name` / `proc_file.name` |
| 进程路径 | `proc.path` / `proc_file.path` |
| 进程命令行 | `proc.cmdline` |
| 进程PID | `proc.pid` |
| 文件MD5 | `proc_file.md5` |
| 文件SHA256 | `proc_file.sha256` |

### 父进程信息

| 中文名 | JSON 字段 |
|-------|-----------|
| 父进程名称 | `pproc.name` |
| 父进程路径 | `pproc.path` |
| 父进程命令行 | `pproc.cmdline` |
| 父进程PID | `pproc.pid` |

### 网络信息

| 中文名 | JSON 字段 |
|-------|-----------|
| 协议 | `net.protocol` |
| 本地IP | `net.local_ip` |
| 本地端口 | `net.local_port` |
| 远端IP | `net.ext_ip` |
| 远端端口 | `net.ext_port` |
| DNS查询域名 | `target` |

## 高频查询示例

按终端查询所有告警：

```sql
host_name = 'LAPTOP-20ECC75'
```

按终端 IP 查询：

```sql
host_ip = '192.168.0.6'
```

只看高危威胁告警：

```sql
threat.level = 'attack' AND threat.severity = '3'
```

查可疑 PowerShell：

```sql
proc.cmdline LIKE '%powershell%' AND proc.cmdline LIKE '%-enc%'
```

查某路径下的可疑进程：

```sql
proc_file.path LIKE '%AppData%Temp%'
```

## 使用建议

- 查询类动作优先从 `onesec_edr` 的 `edr_get_endpoint_alerts` 入手
- 当用户描述的是“页面高级查询条件”时，把条件翻译成这里的字段表达式
- 如果要看图谱、事件概览或 AI 查询面板，再回退浏览器
