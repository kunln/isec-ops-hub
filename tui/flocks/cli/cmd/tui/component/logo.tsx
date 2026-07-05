import { TextAttributes, RGBA } from "@opentui/core"
import { For, type JSX } from "solid-js"
import { useTheme, tint } from "@tui/context/theme"

// Shadow markers (rendered chars in parens):
// _ = full shadow cell (space with bg=shadow)
// ^ = letter top, shadow bottom (▀ with fg=letter, bg=shadow)
// ~ = shadow top only (▀ with fg=shadow)
const SHADOW_MARKER = /[_^~]/

const LOGO_LINES = [
  `███████╗██╗      ██████╗  ██████╗██╗  ██╗███████╗`,
  `██╔════╝██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔════╝`,
  `█████╗  ██║     ██║   ██║██║     █████╔╝ ███████╗`,
  `██╔══╝  ██║     ██║   ██║██║     ██╔═██╗ ╚════██║`,
  `██║     ███████╗╚██████╔╝╚██████╗██║  ██╗███████║`,
  `╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝`,
]

export function Logo() {
  const { theme } = useTheme()

  return (
    <box>
      <For each={LOGO_LINES}>
        {(line) => (
          <box flexDirection="row">
            <text fg={theme.primary} attributes={TextAttributes.BOLD} selectable={false}>
              {line}
            </text>
          </box>
        )}
      </For>
    </box>
  )
}
