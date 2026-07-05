# Flocks TUI 输入性能优化方案

## 问题分析

### 当前实现

在 `flocks/cli/cmd/tui/component/prompt/index.tsx` 中，每次用户输入一个字符都会触发：

```tsx
onContentChange={() => {
  const value = input.plainText
  setStore("prompt", "input", value)           // 1. Store 更新
  autocomplete.onInput(value)                  // 2. 自动补全计算
  syncExtmarksWithPromptParts()                // 3. Extmark 同步
}}
```

### 性能瓶颈

1. **`syncExtmarksWithPromptParts()`**：遍历所有 extmarks 和 parts，更新位置信息
2. **`autocomplete.onInput(value)`**：触发自动补全搜索
3. **Store 更新**：触发 Solid.js 的响应式更新

这些操作在每次按键时都执行，导致输入延迟，特别是当：
- 输入框中有多个 `@file` 或 `@agent` 引用时
- 输入文本较长时
- 自动补全列表较长时

## 解决方案

### 方案 1: 批处理优化（推荐）

使用 `queueMicrotask` 将同步操作延迟到下一个微任务，允许多个快速按键批量处理。

```tsx
let syncScheduled = false

onContentChange={() => {
  const value = input.plainText
  setStore("prompt", "input", value)
  autocomplete.onInput(value)
  
  // 批处理 syncExtmarksWithPromptParts
  if (!syncScheduled) {
    syncScheduled = true
    queueMicrotask(() => {
      syncScheduled = false
      syncExtmarksWithPromptParts()
    })
  }
}}
```

**优点**：
- 极低延迟（微任务级别）
- 保持响应性
- 简单实现

**效果**：
- 快速打字时，多个按键只触发一次 sync
- 延迟：~1ms（微任务）

### 方案 2: 节流优化

使用时间节流，限制 sync 操作的频率。

```tsx
let lastSyncTime = 0
const SYNC_THROTTLE_MS = 16 // 60fps

onContentChange={() => {
  const value = input.plainText
  setStore("prompt", "input", value)
  autocomplete.onInput(value)
  
  const now = Date.now()
  if (now - lastSyncTime >= SYNC_THROTTLE_MS) {
    lastSyncTime = now
    syncExtmarksWithPromptParts()
  }
}}
```

**优点**：
- 保证最低刷新率（60fps）
- 可见的更新频率

**缺点**：
- 可能丢失中间状态
- 需要额外的清理逻辑

### 方案 3: 防抖 + 立即执行

结合防抖和立即执行，提供最佳的用户体验。

```tsx
let syncTimer: Timer | undefined
let lastSyncTime = 0
const SYNC_IMMEDIATE_MS = 16  // 立即执行的间隔
const SYNC_DEBOUNCE_MS = 100  // 防抖延迟

onContentChange(() => {
  const value = input.plainText
  setStore("prompt", "input", value)
  autocomplete.onInput(value)
  
  const now = Date.now()
  const elapsed = now - lastSyncTime
  
  // 清除现有的防抖计时器
  if (syncTimer) clearTimeout(syncTimer)
  
  // 如果距离上次同步超过 16ms，立即执行
  if (elapsed >= SYNC_IMMEDIATE_MS) {
    lastSyncTime = now
    syncExtmarksWithPromptParts()
  } else {
    // 否则，设置防抖计时器
    syncTimer = setTimeout(() => {
      lastSyncTime = Date.now()
      syncExtmarksWithPromptParts()
    }, SYNC_DEBOUNCE_MS)
  }
}}
```

**优点**：
- 最佳的响应性
- 减少不必要的同步
- 平衡实时性和性能

### 方案 4: 条件同步

只在必要时同步（有 extmarks 时）。

```tsx
onContentChange={() => {
  const value = input.plainText
  setStore("prompt", "input", value)
  autocomplete.onInput(value)
  
  // 只有在有 extmarks 时才同步
  const hasExtmarks = input.extmarks.getAllForTypeId(promptPartTypeId).length > 0
  if (hasExtmarks) {
    syncExtmarksWithPromptParts()
  }
}}
```

**优点**：
- 零开销（无 extmarks 时）
- 简单实现

**适用场景**：
- 纯文本输入（无 `@` 引用）时最快

## 推荐实施

### 第一步：批处理优化（立即实施）

修改 `flocks/cli/cmd/tui/component/prompt/index.tsx`:

```tsx
// 在组件顶部添加
let syncScheduled = false

// 修改 textarea 的 onContentChange
<textarea
  ...
  onContentChange={() => {
    const value = input.plainText
    setStore("prompt", "input", value)
    autocomplete.onInput(value)
    
    // 批处理同步
    if (!syncScheduled) {
      syncScheduled = true
      queueMicrotask(() => {
        syncScheduled = false
        syncExtmarksWithPromptParts()
      })
    }
  }}
  ...
/>
```

### 第二步：自动补全优化（可选）

检查 `autocomplete.onInput()` 是否已经有内部节流。如果没有，可以添加：

```tsx
// 在 autocomplete.tsx 中
let inputTimer: Timer | undefined
const INPUT_DEBOUNCE_MS = 50

function onInput(value: string) {
  if (inputTimer) clearTimeout(inputTimer)
  inputTimer = setTimeout(() => {
    // 执行实际的自动补全逻辑
    performAutocomplete(value)
  }, INPUT_DEBOUNCE_MS)
}
```

### 第三步：性能监控

添加性能监控来验证优化效果：

```tsx
let inputCount = 0
let syncCount = 0
let lastReport = Date.now()

onContentChange(() => {
  inputCount++
  
  // ... 优化后的代码 ...
  
  // 每秒报告一次
  const now = Date.now()
  if (now - lastReport > 1000) {
    console.log(`Input: ${inputCount}/s, Sync: ${syncCount}/s`)
    inputCount = 0
    syncCount = 0
    lastReport = now
  }
}}
```

## 预期效果

| 指标 | 优化前 | 优化后 | 改善 |
|-----|--------|--------|------|
| 输入延迟 | 5-10ms | <1ms | 90%+ |
| Sync 频率 | 60次/秒 | 5-10次/秒 | 85%+ |
| CPU 使用 | 中等 | 低 | 60%+ |
| 用户体验 | 可感知延迟 | 无感延迟 | 显著提升 |

## 与 Flocks 对比

Flocks 使用相同的结构，但可能在以下方面有优化：

1. **更少的 extmarks**：Flocks 可能对引用的处理更高效
2. **底层优化**：`@opentui/core` 可能有内部优化
3. **更少的响应式依赖**：Flocks 的状态管理可能更轻量

通过实施上述优化，Flocks TUI 应该能达到与 Flocks 相同甚至更好的性能。

## 测试方法

1. **快速打字测试**：
   ```
   在输入框中快速输入长文本（100+ 字符）
   观察是否有延迟或卡顿
   ```

2. **引用测试**：
   ```
   添加多个 @file 和 @agent 引用
   在引用之间快速输入文本
   观察性能是否下降
   ```

3. **自动补全测试**：
   ```
   输入 @ 触发自动补全
   快速过滤（输入多个字符）
   观察下拉列表的响应速度
   ```

4. **对比测试**：
   ```
   在 Flocks 和 Flocks 中执行相同操作
   记录主观感受和客观指标
   ```
