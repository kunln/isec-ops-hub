# 告警研判通道通知

这个工作流用于把 Flocks 本地安全告警研判结果推送到 IM 通道。

默认流程：

1. 扫描本地安全告警库中未推送过的 `critical` / `high` 告警。
2. 默认只处理 `new` 状态告警。
3. 调用 Flocks 本地 `triage_alert` 逻辑执行关联、规则研判和可选事件创建。
4. 使用工作流状态记录已推送告警 ID，避免重复通知。
5. 通过 `channel_id` 指定的通道发送摘要通知。

关键输入：

- `channel_id`: 通道 ID，默认 `weixin`，也可以填 `wecom`、`feishu`、`dingtalk` 等已配置通道。
- `to`: 目标用户或群 ID。留空时会自动使用该通道最近一次会话绑定。
- `account_id`: 多账号通道可指定账号；留空时优先使用绑定记录。
- `severity_levels`: 严重级别列表，默认 `["critical", "high"]`。
- `statuses`: 告警状态列表，默认 `["new"]`。
- `lookback_minutes`: 回看分钟数，默认 1440；填 0 表示不按时间过滤。
- `max_alerts`: 单次最多研判和通知的告警数。
- `create_incident`: 是否允许研判时自动创建事件，默认 true。
- `dry_run`: true 时只生成预览，不发送、不写去重状态。
- `reset_state`: true 时重置当前通道和目标的去重状态。

绑定说明：

如果 `to` 留空，必须先从目标 IM 通道给 Flocks Bot 发一条消息，让 Flocks 生成 `channel_bindings` 记录。之后定时任务会使用最近一次绑定作为通知目标。
