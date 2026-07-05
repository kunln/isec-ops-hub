import z from "zod"
import path from "path"
import os from "os"
import { Config } from "../config/config"
import { Instance } from "../project/instance"
import { NamedError } from "@flocks-ai/util/error"
import { ConfigMarkdown } from "../config/markdown"
import { Log } from "../util/log"
import { Global } from "@/global"
import { Filesystem } from "@/util/filesystem"
import { Flag } from "@/flag/flag"
import { Bus } from "@/bus"
import { TuiEvent } from "@/cli/cmd/tui/event"
import { Session } from "@/session"

export namespace Skill {
  const log = Log.create({ service: "skill" })
  export const Info = z.object({
    name: z.string(),
    description: z.string(),
    location: z.string(),
  })
  export type Info = z.infer<typeof Info>

  export const InvalidError = NamedError.create(
    "SkillInvalidError",
    z.object({
      path: z.string(),
      message: z.string().optional(),
      issues: z.custom<z.core.$ZodIssue[]>().optional(),
    }),
  )

  export const NameMismatchError = NamedError.create(
    "SkillNameMismatchError",
    z.object({
      path: z.string(),
      expected: z.string(),
      actual: z.string(),
    }),
  )

  const FLOCKS_SKILL_GLOB = new Bun.Glob("{skill,skills}/**/SKILL.md")
  const CLAUDE_SKILL_GLOB = new Bun.Glob("skills/**/SKILL.md")

  export const state = Instance.state(async () => {
    const skills: Record<string, Info> = {}

    const addSkill = async (match: string) => {
      const md = await ConfigMarkdown.parse(match).catch((err) => {
        const message = ConfigMarkdown.FrontmatterError.isInstance(err)
          ? err.data.message
          : `Failed to parse skill ${match}`
        Bus.publish(Session.Event.Error, { error: new NamedError.Unknown({ message }).toObject() })
        log.error("failed to load skill", { skill: match, err })
        return undefined
      })

      if (!md) return

      const parsed = Info.pick({ name: true, description: true }).safeParse(md.data)
      if (!parsed.success) return

      // Warn on duplicate skill names
      if (skills[parsed.data.name]) {
        log.warn("duplicate skill name", {
          name: parsed.data.name,
          existing: skills[parsed.data.name].location,
          duplicate: match,
        })
      }

      skills[parsed.data.name] = {
        name: parsed.data.name,
        description: parsed.data.description,
        location: match,
      }
    }

    // Scan .claude/skills/ directories (project-level)
    const claudeDirs = await Array.fromAsync(
      Filesystem.up({
        targets: [".claude"],
        start: Instance.directory,
        stop: Instance.worktree,
      }),
    )
    // Also include global ~/.claude/skills/
    const globalClaude = `${Global.Path.home}/.claude`
    if (await Filesystem.isDir(globalClaude)) {
      claudeDirs.push(globalClaude)
    }

    if (!Flag.FLOCKS_DISABLE_CLAUDE_CODE_SKILLS) {
      for (const dir of claudeDirs) {
        const matches = await Array.fromAsync(
          CLAUDE_SKILL_GLOB.scan({
            cwd: dir,
            absolute: true,
            onlyFiles: true,
            followSymlinks: true,
            dot: true,
          }),
        ).catch((error) => {
          log.error("failed .claude directory scan for skills", { dir, error })
          return []
        })

        for (const match of matches) {
          await addSkill(match)
        }
      }
    }

    // Scan configuration skill directories
    for (const dir of await Config.directories()) {
      for await (const match of FLOCKS_SKILL_GLOB.scan({
        cwd: dir,
        absolute: true,
        onlyFiles: true,
        followSymlinks: true,
      })) {
        await addSkill(match)
      }
    }

    return skills
  })

  export async function get(name: string) {
    return state().then((x) => x[name])
  }

  export async function all() {
    return state().then((x) => Object.values(x))
  }

  // ---------------------------------------------------------------------------
  // Eligibility check
  // ---------------------------------------------------------------------------

  export function checkEligibility(skill: Info): { eligible: boolean; missing: string[] } {
    const meta = (skill as any).metadata
    const requires = meta?.flocks?.requires ?? meta?.openclaw?.requires ?? null
    if (!requires) return { eligible: true, missing: [] }

    const missing: string[] = []

    if (Array.isArray(requires.bins)) {
      for (const bin of requires.bins as string[]) {
        if (!Bun.which(bin)) missing.push(`bin:${bin}`)
      }
    }
    if (Array.isArray(requires.any_bins)) {
      const anyBins = requires.any_bins as string[]
      if (!anyBins.some((b) => Bun.which(b))) {
        missing.push(`any_bin:${anyBins.join(",")}`)
      }
    }
    if (Array.isArray(requires.env)) {
      for (const v of requires.env as string[]) {
        if (!process.env[v]) missing.push(`env:${v}`)
      }
    }
    return { eligible: missing.length === 0, missing }
  }

  // ---------------------------------------------------------------------------
  // Install skill from external source
  // ---------------------------------------------------------------------------

  export interface InstallResult {
    success: boolean
    skill_name?: string
    location?: string
    message: string
    error?: string
  }

  export interface DepInstallResult {
    success: boolean
    spec_id?: string
    command: string[]
    stdout: string
    stderr: string
    returncode: number
    error?: string
  }

  function resolveSource(source: string): { kind: string; value: string } {
    source = source.trim()
    if (source.startsWith("safeskill:")) return { kind: "safeskill", value: source.slice(10) }
    if (source.startsWith("clawhub:")) return { kind: "clawhub", value: source.slice(8) }
    if (source.startsWith("github:")) return { kind: "github", value: source.slice(7) }
    if (source.startsWith("http://") || source.startsWith("https://")) {
      const ghMatch = source.match(/https?:\/\/github\.com\/([^/]+\/[^/]+)(?:\/tree\/[^/]+)?(\/.*)?$/)
      if (ghMatch) {
        const repo = ghMatch[1].replace(/\/$/, "")
        const sub = (ghMatch[2] ?? "").replace(/^\//, "")
        return { kind: "github", value: sub ? `${repo}/${sub}` : repo }
      }
      return { kind: "url", value: source }
    }
    if (source.startsWith("/") || source.startsWith("./") || source.startsWith("~/")) {
      return { kind: "local", value: source.replace(/^~/, os.homedir()) }
    }
    if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(source)) {
      return { kind: "github", value: source }
    }
    return { kind: "url", value: source }
  }

  function userSkillsRoot(): string {
    return path.join(os.homedir(), ".flocks", "plugins", "skills")
  }

  function isValidName(name: string): boolean {
    return /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)
  }

  async function saveSkillContent(
    content: string,
    scope: string,
    hintName?: string,
  ): Promise<InstallResult> {
    // parse frontmatter for name
    const fmMatch = content.match(/^---\n([\s\S]*?)\n---/)
    const nameMatch = fmMatch ? fmMatch[1].match(/^name:\s*(.+)$/m) : null
    const name = (nameMatch ? nameMatch[1].trim().replace(/['"]/g, "") : hintName ?? "").trim()

    if (!name || !isValidName(name)) {
      return { success: false, message: "", error: `Invalid or missing skill name: "${name}"` }
    }

    const root =
      scope === "project"
        ? path.join(Instance.directory, ".flocks", "plugins", "skills")
        : userSkillsRoot()

    const skillDir = path.join(root, name)
    await Bun.write(path.join(skillDir, "SKILL.md"), content)

    // Invalidate cache
    state.reset?.()

    return {
      success: true,
      skill_name: name,
      location: path.join(skillDir, "SKILL.md"),
      message: `Skill '${name}' installed to ${skillDir}`,
    }
  }

  async function installFromGitHub(repoPath: string, scope: string): Promise<InstallResult> {
    const parts = repoPath.replace(/^\//, "").split("/")
    if (parts.length < 2) {
      return { success: false, message: "", error: `Invalid GitHub path: ${repoPath}` }
    }
    const [owner, repo, ...rest] = parts
    const subpath = rest.join("/")

    const candidatePaths = subpath ? [subpath, `skills/${subpath}`] : [""]

    for (const branch of ["main", "master"]) {
      for (const dirPath of candidatePaths) {
        const result = await downloadGitHubDir(owner, repo, branch, dirPath, scope)
        if (result.success) return result
      }
    }
    return { success: false, message: "", error: `Cannot find SKILL.md in GitHub repo: ${owner}/${repo}` }
  }

  async function downloadGitHubDir(
    owner: string,
    repo: string,
    branch: string,
    dirPath: string,
    scope: string,
  ): Promise<InstallResult> {
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${dirPath}?ref=${branch}`
    const res = await fetch(apiUrl, { headers: { Accept: "application/vnd.github+json" } }).catch(() => null)
    if (!res?.ok) return { success: false, message: "", error: `GitHub API ${res?.status} for ${apiUrl}` }

    const entries: any[] = await res.json()
    if (!Array.isArray(entries)) return { success: false, message: "", error: "Expected directory listing" }

    // Check SKILL.md exists
    const skillMdEntry = entries.find((e) => e.type === "file" && e.name === "SKILL.md")
    if (!skillMdEntry) return { success: false, message: "", error: `No SKILL.md at ${dirPath || "repo root"} branch=${branch}` }

    // Read SKILL.md to get name
    const mdRes = await fetch(skillMdEntry.download_url).catch(() => null)
    if (!mdRes?.ok) return { success: false, message: "", error: "Failed to download SKILL.md" }
    const mdContent = await mdRes.text()

    const nameMatch = mdContent.match(/^---\n[\s\S]*?^name:\s*(.+)$/m)
    const name = nameMatch ? nameMatch[1].trim().replace(/['"]/g, "") : ""
    if (!name || !isValidName(name)) return { success: false, message: "", error: `Invalid skill name: "${name}"` }

    const root =
      scope === "project"
        ? path.join(Instance.directory, ".flocks", "plugins", "skills")
        : userSkillsRoot()
    const skillDir = path.join(root, name)

    // Recursively download all files
    const fileCount = await downloadGitHubEntries(entries, skillDir, "")

    state.reset?.()
    return {
      success: true,
      skill_name: name,
      location: path.join(skillDir, "SKILL.md"),
      message: `Skill '${name}' installed to ${skillDir} (${fileCount} files)`,
    }
  }

  async function downloadGitHubEntries(entries: any[], baseDir: string, relBase: string): Promise<number> {
    let count = 0
    for (const entry of entries) {
      const relPath = relBase ? `${relBase}/${entry.name}` : entry.name
      if (entry.type === "file" && entry.download_url) {
        const res = await fetch(entry.download_url).catch(() => null)
        if (!res?.ok) continue
        const dest = path.join(baseDir, relPath)
        await Bun.write(dest, await res.arrayBuffer())
        count++
      } else if (entry.type === "dir" && entry.url) {
        const subRes = await fetch(entry.url, { headers: { Accept: "application/vnd.github+json" } }).catch(() => null)
        if (!subRes?.ok) continue
        const subEntries = await subRes.json()
        if (Array.isArray(subEntries)) {
          count += await downloadGitHubEntries(subEntries, baseDir, relPath)
        }
      }
    }
    return count
  }

  async function installFromUrl(url: string, scope: string, hintName?: string): Promise<InstallResult> {
    const res = await fetch(url).catch((e) => {
      throw new Error(`Fetch failed: ${e}`)
    })
    if (!res.ok) {
      return { success: false, message: "", error: `HTTP ${res.status} from ${url}` }
    }
    return saveSkillContent(await res.text(), scope, hintName)
  }

  export async function installFromSource(source: string, scope = "global"): Promise<InstallResult> {
    const { kind, value } = resolveSource(source)

    if (kind === "safeskill") {
      return { success: false, message: "", error: "SafeSkill registry not yet available." }
    }
    if (kind === "clawhub") {
      for (const url of [
        `https://registry.clawhub.com/skills/${value}/SKILL.md`,
        `https://clawhub.com/skills/${value}/SKILL.md`,
        `https://raw.githubusercontent.com/clawhub-skills/${value}/main/SKILL.md`,
      ]) {
        const result = await installFromUrl(url, scope, value).catch(() => null)
        if (result?.success) return result
      }
      return { success: false, message: "", error: `Skill '${value}' not found on clawhub.` }
    }
    if (kind === "github") return installFromGitHub(value, scope)
    if (kind === "url") return installFromUrl(value, scope)
    if (kind === "local") {
      let localPath = value
      if (await Filesystem.isDir(localPath)) {
        localPath = path.join(localPath, "SKILL.md")
      }
      const file = Bun.file(localPath)
      if (!(await file.exists())) {
        return { success: false, message: "", error: `File not found: ${localPath}` }
      }
      return saveSkillContent(await file.text(), scope)
    }
    return { success: false, message: "", error: `Unsupported source: ${source}` }
  }

  // ---------------------------------------------------------------------------
  // Install skill dependencies
  // ---------------------------------------------------------------------------

  export async function installDeps(skillName: string, installId?: string): Promise<DepInstallResult[]> {
    const skillMap = await state()
    const skill = skillMap[skillName]
    if (!skill) {
      return [{ success: false, command: [], stdout: "", stderr: "", returncode: 1, error: `Skill not found: ${skillName}` }]
    }

    const meta = (skill as any).metadata
    const specs: any[] = meta?.flocks?.install ?? meta?.openclaw?.install ?? []
    if (specs.length === 0) {
      return [{ success: true, command: [], stdout: "", stderr: "", returncode: 0, message: `No install specs for '${skillName}'` } as any]
    }

    const toRun = installId ? specs.filter((s) => s.id === installId) : specs

    const results: DepInstallResult[] = []
    for (const spec of toRun) {
      const cmd = buildInstallCommand(spec)
      if (!cmd) {
        results.push({ success: false, spec_id: spec.id, command: [], stdout: "", stderr: "", returncode: 1, error: `Cannot build command for kind=${spec.kind}` })
        continue
      }
      try {
        const proc = Bun.spawnSync(cmd, { stdout: "pipe", stderr: "pipe", timeout: 300_000 })
        const stdout = proc.stdout?.toString() ?? ""
        const stderr = proc.stderr?.toString() ?? ""
        const returncode = proc.exitCode ?? 0
        results.push({ success: returncode === 0, spec_id: spec.id, command: cmd, stdout, stderr, returncode })
      } catch (e: any) {
        results.push({ success: false, spec_id: spec.id, command: cmd, stdout: "", stderr: "", returncode: 1, error: String(e) })
      }
    }
    return results
  }

  function buildInstallCommand(spec: any): string[] | null {
    if (spec.kind === "brew" && spec.formula) return ["brew", "install", spec.formula]
    if (spec.kind === "npm" && spec.package) return ["npm", "install", "-g", "--ignore-scripts", spec.package]
    if (spec.kind === "uv" && spec.package) return ["uv", "tool", "install", spec.package]
    if (spec.kind === "pip" && spec.package) return ["python3", "-m", "pip", "install", spec.package]
    if (spec.kind === "go" && (spec.module ?? spec.package)) return ["go", "install", spec.module ?? spec.package]
    return null
  }
}
