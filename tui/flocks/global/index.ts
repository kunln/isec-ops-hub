import fs from "fs/promises"
import path from "path"
import os from "os"

const app = "flocks"

/**
 * Get flocks root directory
 * Default: ~/.flocks
 * Override: FLOCKS_ROOT environment variable
 */
function getFlocksRoot(): string {
  return process.env.FLOCKS_ROOT || path.join(os.homedir(), `.${app}`)
}

const root = getFlocksRoot()

export namespace Global {
  export const Path = {
    /**
     * User home directory
     * Can be overridden by FLOCKS_TEST_HOME for testing
     */
    get home() {
      return process.env.FLOCKS_TEST_HOME || os.homedir()
    },
    
    /** Root directory: ~/.flocks */
    root,
    
    /** Data directory: ~/.flocks/data */
    data: process.env.FLOCKS_DATA_DIR || path.join(root, "data"),
    
    /** Config directory: ~/.flocks/config */
    config: process.env.FLOCKS_CONFIG_DIR || path.join(root, "config"),
    
    /** Log directory: ~/.flocks/logs */
    log: process.env.FLOCKS_LOG_DIR || path.join(root, "logs"),
    
    /** Binary tools directory: ~/.flocks/bin */
    bin: path.join(process.env.FLOCKS_DATA_DIR || path.join(root, "data"), "bin"),
    
    /** Cache directory: ~/.flocks/cache */
    cache: process.env.FLOCKS_CACHE_DIR || path.join(root, "cache"),
    
    /** State directory (alias for root, for compatibility) */
    state: root,
    
    /** Memory directory: ~/.flocks/data/memory (统一存储) */
    memory: path.join(process.env.FLOCKS_DATA_DIR || path.join(root, "data"), "memory"),

    /** Workspace directory: ~/.flocks/workspace */
    workspace: process.env.FLOCKS_WORKSPACE_DIR || path.join(root, "workspace"),
  }
}

// Create all required directories
await Promise.all([
  fs.mkdir(Global.Path.data, { recursive: true }),
  fs.mkdir(Global.Path.config, { recursive: true }),
  fs.mkdir(Global.Path.log, { recursive: true }),
  fs.mkdir(Global.Path.bin, { recursive: true }),
  fs.mkdir(Global.Path.cache, { recursive: true }),
  fs.mkdir(Global.Path.workspace, { recursive: true }),
])

// Note: Memory directory (data/memory/) is created by Python backend

const CACHE_VERSION = "18"

const version = await Bun.file(path.join(Global.Path.cache, "version"))
  .text()
  .catch(() => "0")

if (version !== CACHE_VERSION) {
  try {
    const contents = await fs.readdir(Global.Path.cache)
    await Promise.all(
      contents.map((item) =>
        fs.rm(path.join(Global.Path.cache, item), {
          recursive: true,
          force: true,
        }),
      ),
    )
  } catch (e) {}
  await Bun.file(path.join(Global.Path.cache, "version")).write(CACHE_VERSION)
}
