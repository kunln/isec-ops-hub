import { createMemo, Match, onCleanup, onMount, Show, Switch } from "solid-js"
import { useTheme } from "../../context/theme"
import { useSync } from "../../context/sync"
import { useDirectory } from "../../context/directory"
import { useConnected } from "../../component/dialog-model"
import { createStore } from "solid-js/store"
import { useRoute } from "../../context/route"
import type { AssistantMessage } from "@flocks-ai/sdk/v2"

const ExecutionStatus = (props: { sessionID: string }) => {
  const sync = useSync()
  const { theme } = useTheme()
  const messages = createMemo(() => sync.data.message[props.sessionID] ?? [])
  
  // Check if session is currently working
  const isWorking = createMemo(() => {
    return sync.session.status(props.sessionID) === "working"
  })
  
  // Get current execution info (model being used)
  const executionInfo = createMemo(() => {
    if (!isWorking()) return null
    const last = messages().findLast((x) => x.role === "assistant" && !x.time.completed) as AssistantMessage
    if (!last) return null
    return {
      provider: last.providerID,
      model: last.modelID,
    }
  })
  
  return (
    <Show when={isWorking() && executionInfo()}>
      <text fg={theme.text}>
        <span style={{ fg: theme.textInfo, bold: true }}>Build</span>{" "}
        {executionInfo()!.provider}: {executionInfo()!.model}
        <span style={{ fg: theme.textMuted }}> esc interrupt</span>
      </text>
    </Show>
  )
}

export function Footer() {
  const { theme } = useTheme()
  const sync = useSync()
  const route = useRoute()
  const mcp = createMemo(() => Object.values(sync.data.mcp).filter((x) => x.status === "connected").length)
  const mcpError = createMemo(() => Object.values(sync.data.mcp).some((x) => x.status === "failed"))
  const lsp = createMemo(() => Object.keys(sync.data.lsp))
  const permissions = createMemo(() => {
    if (route.data.type !== "session") return []
    return sync.data.permission[route.data.sessionID] ?? []
  })
  const directory = useDirectory()
  const connected = useConnected()
  const sessionID = createMemo(() => route.data.type === "session" ? route.data.sessionID : null)

  const [store, setStore] = createStore({
    welcome: false,
  })

  onMount(() => {
    // Track all timeouts to ensure proper cleanup
    const timeouts: ReturnType<typeof setTimeout>[] = []

    function tick() {
      if (connected()) return
      if (!store.welcome) {
        setStore("welcome", true)
        timeouts.push(setTimeout(() => tick(), 5000))
        return
      }

      if (store.welcome) {
        setStore("welcome", false)
        timeouts.push(setTimeout(() => tick(), 10_000))
        return
      }
    }
    timeouts.push(setTimeout(() => tick(), 10_000))

    onCleanup(() => {
      timeouts.forEach(clearTimeout)
    })
  })

  return (
    <box flexDirection="row" justifyContent="space-between" gap={1} flexShrink={0}>
      <box flexDirection="row" gap={2} flexShrink={0}>
        <Show when={sessionID()} fallback={<text fg={theme.textMuted}>{directory()}</text>}>
          <Show when={sync.session.status(sessionID()!) === "working"} fallback={<text fg={theme.textMuted}>{directory()}</text>}>
            <ExecutionStatus sessionID={sessionID()!} />
          </Show>
        </Show>
      </box>
      <box gap={2} flexDirection="row" flexShrink={0}>
        <Switch>
          <Match when={store.welcome}>
            <text fg={theme.text}>
              Get started <span style={{ fg: theme.textMuted }}>/connect</span>
            </text>
          </Match>
          <Match when={connected()}>
            <Show when={permissions().length > 0}>
              <text fg={theme.warning}>
                <span style={{ fg: theme.warning }}>△</span> {permissions().length} Permission
                {permissions().length > 1 ? "s" : ""}
              </text>
            </Show>
            <text fg={theme.text}>
              <span style={{ fg: lsp().length > 0 ? theme.success : theme.textMuted }}>•</span> {lsp().length} LSP
            </text>
            <Show when={mcp()}>
              <text fg={theme.text}>
                <Switch>
                  <Match when={mcpError()}>
                    <span style={{ fg: theme.error }}>⊙ </span>
                  </Match>
                  <Match when={true}>
                    <span style={{ fg: theme.success }}>⊙ </span>
                  </Match>
                </Switch>
                {mcp()} MCP
              </text>
            </Show>
            <text fg={theme.textMuted}>/status</text>
          </Match>
        </Switch>
      </box>
    </box>
  )
}
