# Flocks TUI

Terminal User Interface for Flocks project.

## Directory Structure

```
tui/
├── flocks/            # Flocks TUI core source code
│   ├── cli/cmd/tui/  # TUI main code
│   ├── provider/     # AI Provider
│   ├── tool/         # Tools
│   ├── lsp/          # LSP
│   └── ...           # Other modules
├── sdk/               # SDK client
├── util/              # Utility functions
├── src/               # TUI entry point
│   └── index.ts       # Main entry file
├── package.json       # Dependency configuration
├── tsconfig.json      # TypeScript configuration
├── bunfig.toml        # Bun runtime configuration (important!)
└── node_modules/      # Installed dependencies
```

## Key Files

### bunfig.toml
This is the **most important** configuration file, telling Bun how to preload SolidJS JSX transformer:

```toml
preload = ["@opentui/solid/preload"]
```

Without this file, Bun cannot properly handle JSX syntax and will throw an error:
```
Export named 'jsxDEV' not found in module
```

### tsconfig.json
Configures path aliases for cleaner import paths:

```json
{
  "paths": {
    "@/*": ["./flocks/*"],
    "@tui/*": ["./flocks/cli/cmd/tui/*"],
    "@flocks-ai/sdk/v2": ["./sdk/v2/index.ts"]
  }
}
```

## Usage

### 1. Install Dependencies

```bash
# In tui directory
cd tui
bun install
```

### 2. Run TUI Standalone

```bash
# Connect to running server
bun run --conditions=browser ./src/index.ts attach http://localhost:8000
```

### 3. Use flocks tui Command (Recommended)

```bash
# Automatically start backend and frontend
flocks tui

# Specify project directory
flocks tui -d /path/to/project

# Specify port
flocks tui -p 8080

# Continue existing session
flocks tui -s <session-id>
```

The `flocks tui` command will:
1. Start Flocks API server in background (default port 8000)
2. Wait for server to be ready
3. Start TUI frontend connecting to server
4. Automatically clean up server process when TUI exits

## Tech Stack

- **Bun**: JavaScript/TypeScript runtime
- **SolidJS**: Reactive UI framework
- **OpenTUI**: Terminal UI framework
- **TypeScript**: Type safety

## Dependencies

Key dependencies:
- `solid-js`: 1.9.10
- `@opentui/core`: 0.1.74
- `@opentui/solid`: 0.1.74
- `zod`: 4.1.8
- etc...

## Troubleshooting

### JSX Runtime Error
If you encounter `Export named 'jsxDEV' not found` error, ensure:
1. `bunfig.toml` file exists
2. `@opentui/solid` package is correctly installed

### Dependency Installation Failed
```bash
# Clean and reinstall
rm -rf node_modules bun.lockb
bun install
```

### Bun Version Issue
Ensure compatible Bun version is used:
```bash
bun --version  # Should be 1.3.5 or higher
```

## Development Notes

### Key Customizations
1. Directory rename: `flocks/` → `flocks/`
2. `flocks/cli/cmd/tui/routes/session/index.tsx` - Fixed import path for `parsers-config.ts`
3. `flocks/cli/cmd/tui/component/logo.tsx` - Updated to Flocks Logo
4. `flocks/cli/ui.ts` - Updated CLI Logo
5. `src/index.ts` - Custom entry file with simplified CLI commands
6. Configuration path: `.flocks/` → `.flocks/`
7. Theme: `flocks.json` → `flocks.json`

## More Information

- OpenTUI framework: https://github.com/anomalyco/opentui
