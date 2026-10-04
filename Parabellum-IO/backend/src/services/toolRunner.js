/**
 * toolRunner.js — shared helpers for running external security CLIs.
 * Uses spawn without a shell so project paths with spaces or special
 * characters are passed safely as single arguments.
 */
import { spawn } from "child_process";

/**
 * Run a command and collect its output. Never rejects on a non-zero exit code
 * (scanners use exit codes to signal "findings found"); rejects only if the
 * program cannot be started or times out.
 * @returns {Promise<{code: number, stdout: string, stderr: string}>}
 */
export function runTool(cmd, args, { cwd = process.cwd(), timeout = 60000, env = process.env } = {}) {
  return new Promise((resolve, reject) => {
    // On Windows, npm-installed CLIs (snyk.cmd) can only be started through a shell,
    // so quote every argument; elsewhere no shell is used at all.
    const isWin = process.platform === "win32";
    const finalArgs = isWin ? args.map(a => `"${String(a).replace(/"/g, '\\"')}"`) : args;
    const finalCmd = isWin && /\s/.test(cmd) ? `"${cmd}"` : cmd;
    const proc = spawn(finalCmd, finalArgs, { cwd, env, shell: isWin, windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error(`${cmd} timed out after ${Math.round(timeout / 1000)}s`));
    }, timeout);

    proc.stdout.on("data", d => { stdout += d.toString(); });
    proc.stderr.on("data", d => { stderr += d.toString(); });
    proc.on("error", err => {
      clearTimeout(timer);
      reject(err.code === "ENOENT" ? Object.assign(new Error(`${cmd} is not installed or not in PATH`), { notInstalled: true }) : err);
    });
    proc.on("close", code => {
      clearTimeout(timer);
      // Windows shells report a missing command as exit code 9009 / "not recognized"
      if (isWin && (code === 9009 || /is not recognized as an internal or external command/i.test(stderr))) {
        return reject(Object.assign(new Error(`${cmd} is not installed or not in PATH`), { notInstalled: true }));
      }
      resolve({ code, stdout, stderr });
    });
  });
}

/** Returns the first line of `<cmd> <versionArgs>` or null if the tool is missing. */
export async function getToolVersion(cmd, versionArgs = ["--version"], timeout = 15000) {
  try {
    const { code, stdout, stderr } = await runTool(cmd, versionArgs, { timeout });
    if (code !== 0) return null;
    return (stdout || stderr).trim().split("\n")[0].trim() || null;
  } catch {
    return null;
  }
}

/** Parse JSON that may be preceded by warning lines. */
export function parseJsonOutput(raw, toolName) {
  try {
    return JSON.parse(raw);
  } catch {
    const start = raw.search(/[{[]/);
    if (start >= 0) {
      try { return JSON.parse(raw.substring(start)); } catch { /* fall through */ }
    }
    throw new Error(`Failed to parse ${toolName} output as JSON: ${raw.substring(0, 300)}`);
  }
}

/** Return the 1-based line number of the first match of `needle`, or null. */
export function lineOf(content, needle) {
  const idx = content.indexOf(needle);
  return idx < 0 ? null : content.substring(0, idx).split("\n").length;
}

/**
 * Blank out // and /* *\/ comments (keeping line breaks so line numbers stay right),
 * so built-in keyword checks do not fire on comments.
 */
export function stripJsComments(content) {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (m, p1) => p1 + " ".repeat(m.length - p1.length));
}
