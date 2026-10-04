// Must be the first import: ESM runs imports before the module body, so a later
// dotenv.config() call would leave process.env empty while other modules load.
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "node:path";
import { fileURLToPath } from "node:url";

import authRouter from "./routes/auth.js";
import analysisRouter from "./routes/analysis.js";
import projectsRouter from "./routes/projects.js";
import sonarRouter from "./routes/sonar.js";
import ragRouter from "./routes/rag.js";
import adminRouter from "./routes/admin.js";
import complianceRouter from "./routes/compliance.js";
import riskRouter from "./routes/risk.js";
import policiesRouter from "./routes/policies.js";
import toolsRouter from "./routes/tools.js";
import pipelineRouter from "./routes/pipeline.js";
import findingsRouter from "./routes/findings.js";
import reportRouter from "./routes/report.js";
import { requireAuth } from "./middleware/authMiddleware.js";
import { verifyEmailConfig } from "./services/emailService.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// React production build lives here after `npm run build` in frontend/
const REACT_DIST = path.join(__dirname, "..", "..", "frontend", "dist");

const app = express();

// Security headers (CSP, X-Frame-Options, HSTS, ...)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
    },
  },
}));

// Only the frontend may call the API from a browser
const allowedOrigins = (process.env.FRONTEND_URL || "http://localhost:5173,http://localhost:4000")
  .split(",").map(o => o.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins }));

app.use(express.json({ limit: "2mb" }));

// Slow down password / OTP guessing
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT) || 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please wait 15 minutes and try again." },
});
app.use(["/api/auth/login", "/api/auth/verify-otp", "/api/auth/signup", "/api/auth/forgot-password", "/api/auth/reset-password", "/api/auth/change-password"], authLimiter);

// ── Serve React static files ───────────────────────────────────────
app.use(express.static(REACT_DIST));

// ── Request logger ─────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.url.startsWith("/api/")) console.log(`➡ ${req.method} ${req.url}`);
  next();
});

// ── Public routes (no auth) ────────────────────────────────────────
app.use("/api/auth", authRouter);

// ── Protected routes (require valid JWT) ──────────────────────────
app.use("/api/projects",    requireAuth, projectsRouter);
app.use("/api/sonar",       requireAuth, sonarRouter);
app.use("/api/analysis",    requireAuth, analysisRouter);
app.use("/api/rag",         requireAuth, ragRouter);
app.use("/api/compliance",  requireAuth, complianceRouter);
app.use("/api/risk",        requireAuth, riskRouter);
app.use("/api/policies",    requireAuth, policiesRouter);
app.use("/api/tools",       requireAuth, toolsRouter);
app.use("/api/pipeline",    requireAuth, pipelineRouter);
app.use("/api/findings",    requireAuth, findingsRouter);
app.use("/api/report",      requireAuth, reportRouter);
app.use("/api/admin",       adminRouter);   // admin router has its own auth + role check

// ── SPA catch-all: serve index.html for all non-API routes ─────────
// React Router handles /login, /dashboard, etc. client-side
app.get("*", (req, res) => {
  if (req.url.startsWith("/api/")) {
    res.status(404).json({ error: `Route not found: ${req.method} ${req.url}` });
  } else {
    res.sendFile(path.join(REACT_DIST, "index.html"));
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`✅ Backend running on port ${port}`);
  console.log(`   🌐 Open frontend: http://localhost:${port}`);
  verifyEmailConfig();
}).on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`❌ Port ${port} is already in use. Close the other backend window or set PORT in backend/.env.`);
    process.exit(1);
  }
  throw err;
});
