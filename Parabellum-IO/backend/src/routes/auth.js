/**
 * auth.js — Authentication routes
 * POST /api/auth/signup       — register new user (one account per e-mail)
 * POST /api/auth/login        — verify password → e-mail OTP (also used to resend, 60 s cooldown)
 * POST /api/auth/verify-otp   — verify OTP → open a saved session, return JWT
 * GET  /api/auth/me           — current user (restores the session after a restart/reload)
 * GET  /api/auth/sessions     — signed-in devices of the current user
 * POST /api/auth/logout       — end this session ({ all: true } ends every session)
 * POST /api/auth/forgot-password — send a password reset code (same delivery as the login OTP)
 * POST /api/auth/reset-password  — { email, code, newPassword } → new password, all sessions signed out
 * POST /api/auth/change-password — signed in: { currentPassword, newPassword }
 *
 * The first admin is created by setting ADMIN_EMAIL in backend/.env
 * (that account gets the admin role on sign-up / next login).
 */
import express from "express";
import {
    signup, login, verifyOtp, getUserById, revokeSession, listSessions,
    forgotPassword, resetPassword, changePassword,
} from "../services/authService.js";
import { requireAuth } from "../middleware/authMiddleware.js";

const router = express.Router();

const fail = (res, err) => res.status(err.status || 500).json({ error: err.message, code: err.code });

// ── POST /api/auth/signup ──────────────────────────────────────────
router.post("/signup", async (req, res) => {
    try {
        const { name, email, password, organization } = req.body;
        const { user } = await signup({ name, email, password, organization });
        res.status(201).json({
            message: "Account created successfully. Please log in.",
            user: { id: user.id, name: user.name, email: user.email },
        });
    } catch (err) { fail(res, err); }
});

// ── POST /api/auth/login ───────────────────────────────────────────
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        res.json(await login({ email, password }));
    } catch (err) { fail(res, err); }
});

// ── POST /api/auth/verify-otp ──────────────────────────────────────
router.post("/verify-otp", (req, res) => {
    try {
        const { email, code, remember } = req.body;
        res.json(verifyOtp({
            email, code, remember: remember === true,
            userAgent: req.headers["user-agent"] || "", ip: req.ip,
        }));
    } catch (err) { fail(res, err); }
});

// ── GET /api/auth/me ───────────────────────────────────────────────
router.get("/me", requireAuth, (req, res) => {
    const user = getUserById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    res.json({ user });
});

// ── GET /api/auth/sessions ─────────────────────────────────────────
router.get("/sessions", requireAuth, (req, res) => {
    res.json({
        current: req.user.sid || null,
        sessions: listSessions(req.user.userId),
    });
});

// ── POST /api/auth/logout ──────────────────────────────────────────
router.post("/logout", requireAuth, (req, res) => {
    revokeSession(req.user, { all: req.body?.all === true });
    res.json({ message: "Logged out successfully." });
});

// ── Password reset / change ────────────────────────────────────────
router.post("/forgot-password", async (req, res) => {
    try { res.json(await forgotPassword({ email: req.body?.email })); } catch (err) { fail(res, err); }
});

router.post("/reset-password", async (req, res) => {
    try {
        const { email, code, newPassword } = req.body || {};
        res.json(await resetPassword({ email, code, newPassword }));
    } catch (err) { fail(res, err); }
});

router.post("/change-password", requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body || {};
        res.json(await changePassword({ userId: req.user.userId, sid: req.user.sid, currentPassword, newPassword }));
    } catch (err) { fail(res, err); }
});

export default router;
