import axios from "axios";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { compileJavaProject } from "./javaCompileService.js";

// sonarqube-scanner is CommonJS — .default gives us the actual function
const require = createRequire(import.meta.url);
const scanner = require("sonarqube-scanner").default;

/**
 * Axios instance pre-configured for SonarQube Web API.
 */
function getSonarClient() {
    const baseURL = process.env.SONARQUBE_URL || "http://localhost:9000";
    const token = process.env.SONARQUBE_TOKEN || "";
    return axios.create({
        baseURL,
        auth: { username: token, password: "" },
        headers: { "Content-Type": "application/json" },
        timeout: 15000,
    });
}

/**
 * Check that SonarQube is reachable and UP (used by the Tools page).
 * @returns {Promise<{available: boolean, version: string|null, url: string, error?: string}>}
 */
export async function checkSonarAvailability() {
    const url = process.env.SONARQUBE_URL || "http://localhost:9000";
    try {
        const { data } = await getSonarClient().get("/api/system/status", { timeout: 5000 });
        const up = data?.status === "UP";
        return {
            available: up && !!process.env.SONARQUBE_TOKEN,
            version: data?.version || null,
            url,
            error: !up ? `SonarQube status: ${data?.status}` :
                !process.env.SONARQUBE_TOKEN ? "SONARQUBE_TOKEN is not set" : undefined,
        };
    } catch (err) {
        return { available: false, version: null, url, error: `Cannot reach SonarQube at ${url}` };
    }
}

/**
 * Create a SonarQube project if it does not already exist.
 */
export async function createSonarProject(projectKey, projectName) {
    const client = getSonarClient();
    const sonarUrl = process.env.SONARQUBE_URL || "http://localhost:9000";
    const sonarToken = process.env.SONARQUBE_TOKEN || "";

    if (!sonarToken) {
        throw new Error(
            `SONARQUBE_TOKEN is not set in backend/.env. ` +
            `Generate one at ${sonarUrl}/account/security`
        );
    }

    try {
        await client.post(
            "/api/projects/create",
            new URLSearchParams({ project: projectKey, name: projectName, visibility: "private" }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
        console.log(`✅ SonarQube project created: ${projectKey}`);
    } catch (err) {
        if (err.response?.status === 400) {
            console.log(`ℹ️  SonarQube project already exists: ${projectKey}`);
        } else if (err.response?.status === 401) {
            throw new Error(`SonarQube auth failed (401) — check SONARQUBE_TOKEN in backend/.env`);
        } else if (err.code === "ECONNREFUSED") {
            throw new Error(`Cannot connect to SonarQube at ${sonarUrl} — is SonarQube running?`);
        } else {
            throw new Error(
                `SonarQube project creation failed: ${err.response?.data?.errors?.[0]?.msg || err.message}`
            );
        }
    }
}

/**
 * Build the full deep-scan SonarQube options for all supported languages.
 * Enables maximum coverage for: Java, Python, JavaScript/TypeScript,
 * PHP, C#, Go, Ruby, Kotlin, Scala, YAML, XML, Docker, Shell, Terraform, etc.
 */
function buildScanOptions(projectKey, projectName, sourceDir, binariesDir) {
    return {
        "sonar.projectKey": projectKey,
        "sonar.projectName": projectName,
        // Base dir MUST be the project folder, otherwise the scanner uses the backend's
        // working directory and silently ignores every file outside it (0 issues, fake PASS).
        "sonar.projectBaseDir": sourceDir,
        "sonar.sources": ".",
        // Keep the scanner's temp files out of the user's project folder
        "sonar.working.directory": path.join(os.tmpdir(), "parabellum-sonar", projectKey),
        "sonar.sourceEncoding": "UTF-8",

        // ── Java deep scan ──────────────────────────────────────────
        // binariesDir is set to the compiled classes dir (or "." fallback)
        "sonar.java.binaries": binariesDir,
        "sonar.java.source": "11",
        "sonar.java.target": "11",

        // ── Python ──────────────────────────────────────────────────
        "sonar.python.version": "3",

        // ── JavaScript / TypeScript ─────────────────────────────────
        "sonar.javascript.node.maxspace": "4096",

        // ── All-language coverage maximisation ──────────────────────
        // Scan ALL files regardless of known extension
        "sonar.inclusions": "**/*",

        // Only skip files that are never meaningful to scan
        "sonar.exclusions": [
            "**/node_modules/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",          // Java build artifacts already in binariesDir
            "**/target/classes/**", // Maven compiled classes (already indexed via binaries)
            "**/*.min.js",
            "**/*.min.css",
            "**/*.map",
            "**/*.lock",
            "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.ico",
            "**/*.zip", "**/*.tar", "**/*.gz", "**/*.jar", "**/*.war",
        ].join(","),

        // ── Security: scan all languages for security hotspots ──────
        "sonar.security.config.enabled": "true",

        // ── SCM: disable if no git history (uploaded ZIPs) ──────────
        "sonar.scm.disabled": "true",

        "sonar.qualitygate.wait": "false",   // don't block for QG — we fetch it after

        // ── Verbose: see all sensor output in console ────────────────
        "sonar.log.level": "INFO",
    };
}

/**
 * Run a full deep SonarQube scan.
 * 1. Auto-compiles Java projects (Maven / Gradle / javac) for full SAST
 * 2. Runs sonarqube-scanner with maximum language coverage options
 *
 * @returns {Promise<{projectKey, compileInfo}>}
 */
export async function runSonarScan(projectKey, projectName, sourceDir) {
    const sonarUrl = process.env.SONARQUBE_URL || "http://localhost:9000";
    const sonarToken = process.env.SONARQUBE_TOKEN || "";

    if (!sonarToken) {
        throw new Error("SONARQUBE_TOKEN is not set in backend/.env");
    }

    // ── Step 1: Auto-compile Java ──────────────────────────────────
    const compileInfo = await compileJavaProject(sourceDir);
    const binariesDir = compileInfo.binariesDir;

    if (compileInfo.method !== "none") {
        if (compileInfo.success) {
            console.log(`✅ Java compilation succeeded. Binaries: ${binariesDir}`);
        } else {
            console.warn(`⚠️  Java compilation failed — using source-only fallback (binariesDir = ".")`);
        }
    }

    // ── Step 2: Run scanner ────────────────────────────────────────
    const options = buildScanOptions(projectKey, projectName, sourceDir, binariesDir);
    console.log(`🔍 Starting Deep SonarQube scan for "${projectKey}"...`);
    console.log(`   Source: ${sourceDir}`);
    console.log(`   Java binaries: ${binariesDir} (${compileInfo.success ? "compiled" : "fallback"})`);

    await new Promise((resolve, reject) => {
        scanner(
            { serverUrl: sonarUrl, token: sonarToken, options },
            (err) => {
                if (err) {
                    console.error("❌ sonarqube-scanner error:", err.message);
                    reject(new Error(`sonar-scanner failed: ${err.message}`));
                } else {
                    console.log(`✅ Deep scan completed for ${projectKey}`);
                    resolve();
                }
            }
        );
    });

    return { projectKey, compileInfo };
}

export async function getScanStatus(projectKey) {
    const client = getSonarClient();
    const { data } = await client.get("/api/ce/component", {
        params: { component: projectKey },
    });
    const current = data.current;
    if (!current) return { status: "NONE", message: "No analysis has been run yet.", queued: (data.queue || []).length };
    return {
        queued: (data.queue || []).length,
        status: current.status,
        taskId: current.id,
        submittedAt: current.submittedAt,
        executedAt: current.executedAt,
        duration: current.executionTimeMs,
        errorMessage: current.errorMessage || null,
    };
}

/**
 * Poll the Compute Engine task status until it finishes processing.
 * SonarQube processes scans asynchronously, so we must wait before fetching issues.
 */
export async function waitForSonarQubeProcessing(projectKey, maxAttempts = 90, intervalMs = 2000, since = null) {
    console.log(`⏳ Waiting for SonarQube to process the report for ${projectKey}...`);
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const { status, errorMessage, queued, submittedAt } = await getScanStatus(projectKey);
            // The report we just uploaded must be processed — not an older analysis
            const isOurs = !since || (submittedAt && new Date(submittedAt).getTime() >= since.getTime() - 5000);
            if (status === "SUCCESS" && !queued && isOurs) {
                console.log(`✅ SonarQube processing complete for ${projectKey}`);
                return;
            }
            if (status === "FAILED" || status === "CANCELED") {
                throw new Error(`SonarQube processing ${status}: ${errorMessage || "Unknown error"}`);
            }
        } catch (err) {
            if (err.response && (err.response.status === 403 || err.response.status === 401)) {
                console.log(`⚠️ SonarQube token lacks permission for CE task API. Falling back to fixed 8s delay.`);
                await new Promise(r => setTimeout(r, 8000));
                return;
            }
            throw err;
        }
        await new Promise(r => setTimeout(r, intervalMs));
    }
    throw new Error(`Timeout waiting for SonarQube to process ${projectKey}`);
}

/**
 * Fetch issues for a project (paginated).
 */
export async function getIssues(projectKey, { pageSize = 100, page = 1 } = {}) {
    const client = getSonarClient();
    const { data } = await client.get("/api/issues/search", {
        params: { componentKeys: projectKey, ps: pageSize, p: page, resolved: false },
    });
    return {
        total: data.paging.total,
        page: data.paging.pageIndex,
        pageSize: data.paging.pageSize,
        issues: data.issues.map((i) => ({
            key: i.key,
            type: i.type,
            severity: i.severity,
            rule: i.rule,
            message: i.message,
            component: i.component,
            line: i.line || null,
            effort: i.effort || null,
            status: i.status,
        })),
    };
}

/**
 * Get the Quality Gate status for a project.
 */
export async function getQualityGate(projectKey) {
    const client = getSonarClient();
    const { data } = await client.get("/api/qualitygates/project_status", {
        params: { projectKey },
    });
    return {
        status: data.projectStatus.status,
        conditions: data.projectStatus.conditions || [],
    };
}

/**
 * Format issues as readable text for GRC/AI mapping.
 */
export function formatIssuesAsText(issues) {
    if (!issues || issues.length === 0) return "No issues found by SonarQube analysis.";
    return issues
        .map(
            (i, idx) => {
                const lineInfo = i.line ? `, Line: ${i.line}` : "";
                return `${idx + 1}. [${i.severity}] ${i.type} – ${i.message} (Rule: ${i.rule}, File: ${i.component}${lineInfo})`;
            }
        )
        .join("\n");
}
