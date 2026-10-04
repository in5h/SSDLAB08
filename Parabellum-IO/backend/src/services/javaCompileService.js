/**
 * javaCompileService.js
 *
 * Detects the build system of a Java project (Maven, Gradle, or plain javac)
 * and compiles it so SonarQube's Java sensor can perform full deep SAST analysis.
 *
 * Returns the path to the compiled classes directory.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import path from "node:path";

const execAsync = promisify(exec);

/**
 * Detect which build system the project uses.
 * @returns {"maven"|"gradle"|"javac"|null}
 */
function detectBuildSystem(projectDir) {
    if (fs.existsSync(path.join(projectDir, "pom.xml"))) return "maven";
    if (
        fs.existsSync(path.join(projectDir, "build.gradle")) ||
        fs.existsSync(path.join(projectDir, "build.gradle.kts"))
    ) return "gradle";

    // Check if any .java files exist for plain javac
    const hasJava = walkDir(projectDir).some((f) => f.endsWith(".java"));
    if (hasJava) return "javac";

    return null;
}

/** Recursively list all files under a directory */
function walkDir(dir, depth = 0) {
    if (depth > 8) return [];
    try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        const files = [];
        for (const e of entries) {
            const full = path.join(dir, e.name);
            if (e.isDirectory() && !["node_modules", ".git", "build", "target", ".gradle"].includes(e.name)) {
                files.push(...walkDir(full, depth + 1));
            } else if (e.isFile()) {
                files.push(full);
            }
        }
        return files;
    } catch {
        return [];
    }
}

/** Collect all .java source files recursively */
function collectJavaSources(dir) {
    return walkDir(dir).filter((f) => f.endsWith(".java"));
}

/**
 * Compile a Java project using the detected build system.
 *
 * @param {string} projectDir  - Root directory of the extracted project
 * @returns {Promise<{binariesDir: string, method: string, success: boolean, output: string}>}
 */
export async function compileJavaProject(projectDir) {
    const buildSystem = detectBuildSystem(projectDir);

    if (!buildSystem) {
        return { binariesDir: ".", method: "none", success: true, output: "No Java files found." };
    }

    console.log(`☕ Java project detected. Build system: ${buildSystem}`);

    try {
        if (buildSystem === "maven") {
            return await compileMaven(projectDir);
        } else if (buildSystem === "gradle") {
            return await compileGradle(projectDir);
        } else {
            return await compileJavac(projectDir);
        }
    } catch (err) {
        console.warn(`⚠️  Java compilation failed (${buildSystem}): ${err.message}`);
        console.warn("    Continuing scan with source-only analysis (reduced Java coverage).");
        return {
            binariesDir: ".",
            method: buildSystem,
            success: false,
            output: err.message,
        };
    }
}

/** Compile with Maven */
async function compileMaven(projectDir) {
    console.log("☕ Compiling with Maven (mvn compile)...");
    const { stdout, stderr } = await execAsync(
        "mvn compile -q -DskipTests -Dmaven.test.skip=true",
        { cwd: projectDir, timeout: 300_000 }
    );
    const binariesDir = path.join(projectDir, "target", "classes");
    const exists = fs.existsSync(binariesDir);
    return {
        binariesDir: exists ? binariesDir : ".",
        method: "maven",
        success: exists,
        output: stdout + stderr,
    };
}

/** Compile with Gradle */
async function compileGradle(projectDir) {
    console.log("☕ Compiling with Gradle (gradle compileJava)...");
    // Try gradlew first, fall back to gradle
    const gradleCmd = fs.existsSync(path.join(projectDir, "gradlew"))
        ? String.raw`.\\gradlew`
        : "gradle";
    const { stdout, stderr } = await execAsync(
        `${gradleCmd} compileJava -q --no-daemon`,
        { cwd: projectDir, timeout: 300_000 }
    );
    // Standard Gradle output dir
    const binariesDir = path.join(projectDir, "build", "classes", "java", "main");
    const exists = fs.existsSync(binariesDir);
    return {
        binariesDir: exists ? binariesDir : ".",
        method: "gradle",
        success: exists,
        output: stdout + stderr,
    };
}

/** Compile with plain javac */
async function compileJavac(projectDir) {
    console.log("☕ Compiling with javac...");
    const outDir = path.join(projectDir, ".sonar-classes");
    fs.mkdirSync(outDir, { recursive: true });

    const javaFiles = collectJavaSources(projectDir);
    if (javaFiles.length === 0) {
        return { binariesDir: ".", method: "javac", success: false, output: "No .java files found." };
    }

    // Write source list to a file (avoids command-line length limits on Windows)
    const listFile = path.join(projectDir, ".java-sources.txt");
    fs.writeFileSync(listFile, javaFiles.join("\n"), "utf8");

    try {
        const { stdout, stderr } = await execAsync(
            `javac -nowarn -d "${outDir}" @"${listFile}"`,
            { cwd: projectDir, timeout: 300_000 }
        );
        return {
            binariesDir: outDir,
            method: "javac",
            success: true,
            output: stdout + stderr,
        };
    } finally {
        // Clean up temp file
        try { fs.unlinkSync(listFile); } catch { /* ignore */ }
    }
}
