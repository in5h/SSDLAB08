/**
 * prestart.js — runs before `npm start` on Windows, macOS and Linux.
 * 1. Checks that backend/.env exists (copies .env.example the first time).
 * 2. Fills in a random JWT_SECRET if it is still the placeholder.
 * 3. Frees the backend port if an old backend is still running.
 * Never fails the start because of step 3.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const backendDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envFile = path.join(backendDir, ".env");
const example = path.join(backendDir, ".env.example");

if (!fs.existsSync(envFile) && fs.existsSync(example)) {
  fs.copyFileSync(example, envFile);
  console.log("ℹ️  Created backend/.env from .env.example. Edit it (JWT_SECRET, SMTP, SonarQube token) and run again if start-up complains.");
}

try {
  const env = fs.readFileSync(envFile, "utf8");
  const m = env.match(/^\s*JWT_SECRET\s*=(.*)$/m);
  const value = m ? m[1].trim() : "";
  if (!value || value.length < 16 || value.startsWith("your_")) {
    const secret = crypto.randomBytes(32).toString("hex");
    const updated = m ? env.replace(m[0], `JWT_SECRET=${secret}`) : `${env.trimEnd()}\nJWT_SECRET=${secret}\n`;
    fs.writeFileSync(envFile, updated);
    console.log("ℹ️  Generated a random JWT_SECRET in backend/.env.");
  }
} catch { /* no .env — the backend prints what is missing */ }

let port = 4000;
try {
  const m = fs.readFileSync(envFile, "utf8").match(/^\s*PORT\s*=\s*(\d+)/m);
  if (m) port = Number(m[1]);
} catch { /* no .env yet */ }

try {
  const { default: killPort } = await import("kill-port");
  await killPort(port, "tcp");
  console.log(`ℹ️  Stopped the old process on port ${port}.`);
} catch {
  // Nothing was running on the port, or kill-port is not installed — both are fine.
}
