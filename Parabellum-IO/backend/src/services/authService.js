/**
 * authService.js — Signup, login, OTP (e-mail MFA) and persistent sessions.
 *
 * - One account per e-mail address (normalised to lower case + unique index).
 * - OTP codes are stored hashed, expire after 5 minutes, are burned after 5
 *   wrong guesses, and can only be re-sent once every 60 seconds.
 * - Every login creates a row in `sessions`; the JWT carries the session id.
 *   Sessions live in SQLite, so users stay logged in across server restarts
 *   (8 hours, or 30 days with "Remember me") until they log out.
 */
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import db from "../db/database.js";
import { sendOtpEmail, isEmailConfigured } from "./emailService.js";

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16 || JWT_SECRET.startsWith("your_")) {
    // A guessable secret would let anyone forge an admin token — refuse to start.
    console.error("❌ JWT_SECRET is missing or too short in backend/.env (use 16+ random characters).");
    process.exit(1);
}
const SESSION_HOURS = 8;
const REMEMBER_DAYS = 30;
const OTP_EXPIRY_SECONDS = 300;   // 5 minutes
const OTP_RESEND_SECONDS = 60;    // minimum gap between two codes
const MAX_OTP_ATTEMPTS = 5;
const BCRYPT_ROUNDS = 12;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/**
 * How the login code reaches the user (OTP_DELIVERY in .env):
 *   auto   (default) e-mail when SMTP is set up; otherwise — or if sending fails — show it on the login screen
 *   email  e-mail only (login fails if SMTP is not working) — use this on a public server
 *   screen always show it on the login screen (no e-mail)
 *   both   e-mail it and also show it on the screen
 * DEV_MODE=true is kept for old .env files and behaves like "auto".
 */
const OTP_DELIVERY = ["auto", "email", "screen", "both"].includes((process.env.OTP_DELIVERY || "").toLowerCase())
    ? process.env.OTP_DELIVERY.toLowerCase() : "auto";
export function otpDeliveryMode() { return OTP_DELIVERY; }

const httpError = (status, message, extra = {}) => Object.assign(new Error(message), { status, ...extra });

/** Lower-case + trim so "Ali@Mail.com " and "ali@mail.com" are the same account. */
export function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

/** Accounts listed in ADMIN_EMAIL (comma-separated) become admins. */
function isBootstrapAdmin(email) {
    return (process.env.ADMIN_EMAIL || "")
        .split(",").map(normalizeEmail).filter(Boolean)
        .includes(normalizeEmail(email));
}

function hashOtp(userId, code) {
    return crypto.createHmac("sha256", JWT_SECRET).update(`${userId}:${code}`).digest("hex");
}

/** Password strength validation */
function validatePassword(password) {
    if (!password || password.length < 8) return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(password)) return "Password must contain an uppercase letter.";
    if (!/[a-z]/.test(password)) return "Password must contain a lowercase letter.";
    if (!/[0-9]/.test(password)) return "Password must contain a number.";
    if (!/[^A-Za-z0-9]/.test(password)) return "Password must contain a special character.";
    return null;
}

/**
 * Register a new user. Only one account is allowed per e-mail address.
 * @returns {{ user: object }}
 */
export async function signup({ name, email, password, organization = "" }) {
    const cleanEmail = normalizeEmail(email);
    if (!name?.trim()) throw httpError(400, "Name is required.");
    if (!cleanEmail) throw httpError(400, "Email is required.");
    if (!EMAIL_RE.test(cleanEmail)) throw httpError(400, "Please enter a valid e-mail address.");
    const pwdError = validatePassword(password);
    if (pwdError) throw httpError(400, pwdError);

    const existing = db.prepare("SELECT id FROM users WHERE lower(email) = ?").get(cleanEmail);
    if (existing) {
        throw httpError(409, "An account with this e-mail already exists. Please sign in instead.", { code: "EMAIL_EXISTS" });
    }

    // Role is never taken from the request: everyone is an analyst unless listed in ADMIN_EMAIL.
    const role = isBootstrapAdmin(cleanEmail) ? "admin" : "analyst";
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    let result;
    try {
        result = db.prepare(
            "INSERT INTO users (name, email, password_hash, organization, role) VALUES (?, ?, ?, ?, ?)"
        ).run(name.trim(), cleanEmail, hash, String(organization || "").trim(), role);
    } catch (err) {
        // Two sign-ups at the same moment: the unique index still guarantees one account
        if (String(err.code).startsWith("SQLITE_CONSTRAINT")) {
            throw httpError(409, "An account with this e-mail already exists. Please sign in instead.", { code: "EMAIL_EXISTS" });
        }
        throw err;
    }

    const user = db.prepare("SELECT id, name, email, organization, role, created_at FROM users WHERE id = ?")
        .get(result.lastInsertRowid);
    return { user };
}

/**
 * Step 1 of login: check e-mail + password, then e-mail a one-time code.
 * Calling it again within 60 s does not send a new code (resend cooldown).
 * @returns {{ message: string, resendInSeconds: number, devOtp?: string }}
 */
export async function login({ email, password }) {
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !password) throw httpError(400, "Email and password are required.");

    const user = db.prepare("SELECT * FROM users WHERE lower(email) = ?").get(cleanEmail);
    if (!user) throw httpError(401, "Invalid email or password.");

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw httpError(401, "Invalid email or password.");

    if (OTP_DELIVERY === "email" && !isEmailConfigured()) {
        throw httpError(503, "Login is unavailable: OTP_DELIVERY=email but e-mail (SMTP) is not configured. Set EMAIL_USER/EMAIL_PASS in backend/.env, or OTP_DELIVERY=auto.");
    }

    if (isBootstrapAdmin(user.email) && user.role !== "admin") {
        db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(user.id);
    }

    return issueCode(user, "login");
}

/**
 * Create a one-time code for `purpose` (login | reset) and deliver it (e-mail and/or screen,
 * see OTP_DELIVERY). Only the newest code of each purpose is valid; 60 s resend cooldown.
 */
async function issueCode(user, purpose) {
    // Resend cooldown: if a code was sent less than 60 s ago, keep using it
    const recent = db.prepare(
        "SELECT created_at FROM otp_codes WHERE user_id = ? AND used = 0 AND COALESCE(purpose, 'login') = ? ORDER BY id DESC LIMIT 1"
    ).get(user.id, purpose);
    if (recent) {
        const ageSec = (Date.now() - new Date(recent.created_at.replace(" ", "T") + "Z").getTime()) / 1000;
        if (ageSec < OTP_RESEND_SECONDS) {
            const wait = Math.ceil(OTP_RESEND_SECONDS - ageSec);
            return {
                message: `A code was already sent to ${user.email}. You can request a new one in ${wait} s.`,
                resendInSeconds: wait,
            };
        }
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_SECONDS * 1000).toISOString();

    // Only the newest code is valid
    db.prepare("UPDATE otp_codes SET used = 1 WHERE user_id = ? AND used = 0 AND COALESCE(purpose, 'login') = ?").run(user.id, purpose);
    db.prepare(
        "INSERT INTO otp_codes (user_id, code, code_hash, expires_at, purpose) VALUES (?, '', ?, ?, ?)"
    ).run(user.id, hashOtp(user.id, code), expiresAt, purpose);

    const wantEmail = OTP_DELIVERY !== "screen" && isEmailConfigured();
    let emailError = null;
    if (wantEmail) {
        try {
            await sendOtpEmail(user.email, user.name, code, purpose);
        } catch (err) {
            if (OTP_DELIVERY === "email") throw err;
            emailError = err.message;
        }
    }

    const response = { resendInSeconds: OTP_RESEND_SECONDS };
    const showOnScreen = OTP_DELIVERY === "screen" || OTP_DELIVERY === "both" || !wantEmail || !!emailError;
    if (wantEmail && !emailError) {
        response.message = `A 6-digit code was sent to ${user.email}. It expires in 5 minutes.`;
    } else if (emailError) {
        response.message = "The e-mail could not be sent, so your code is shown below. (Fix EMAIL_USER / EMAIL_PASS in backend/.env to receive it by e-mail.)";
    } else {
        response.message = OTP_DELIVERY === "screen"
            ? "Your code is shown below. It expires in 5 minutes."
            : "E-mail is not set up on the server, so your code is shown below. It expires in 5 minutes.";
    }
    if (showOnScreen) {
        response.devOtp = code;
        response.otpShownOnScreen = true;
    }
    return response;
}

/** Create a persistent session row and the JWT that points to it. */
function createSession(user, { remember = false, userAgent = "", ip = "" } = {}) {
    const sid = crypto.randomUUID();
    const ttlMs = remember ? REMEMBER_DAYS * 86400000 : SESSION_HOURS * 3600000;
    const expiresAt = new Date(Date.now() + ttlMs);
    db.prepare(
        "INSERT INTO sessions (id, user_id, remember, user_agent, ip, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(sid, user.id, remember ? 1 : 0, String(userAgent).slice(0, 200), String(ip).slice(0, 64), expiresAt.toISOString());

    const token = jwt.sign(
        { userId: user.id, email: user.email, name: user.name, role: user.role, sid },
        JWT_SECRET,
        { expiresIn: Math.floor(ttlMs / 1000) }
    );
    return { token, expiresAt: expiresAt.toISOString() };
}

/** Check a one-time code of `purpose`; burns it on success or after too many wrong tries. */
function checkCode(user, code, purpose) {
    const otpRow = db.prepare(
        "SELECT * FROM otp_codes WHERE user_id = ? AND used = 0 AND COALESCE(purpose, 'login') = ? ORDER BY id DESC LIMIT 1"
    ).get(user.id, purpose);
    if (!otpRow) throw httpError(401, "No active OTP found. Please request a new code.");

    if (new Date() > new Date(otpRow.expires_at)) {
        db.prepare("UPDATE otp_codes SET used = 1 WHERE id = ?").run(otpRow.id);
        throw httpError(401, "OTP has expired. Please request a new code to receive a new code.");
    }

    const submitted = String(code).trim();
    const expected = otpRow.code_hash || null;
    const ok = expected
        ? crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(hashOtp(user.id, submitted)))
        : otpRow.code === submitted; // codes created before this version

    if (!ok) {
        const attempts = (otpRow.attempts || 0) + 1;
        if (attempts >= MAX_OTP_ATTEMPTS) {
            db.prepare("UPDATE otp_codes SET used = 1, attempts = ? WHERE id = ?").run(attempts, otpRow.id);
            throw httpError(401, "Too many wrong codes. Please request a new code to get a new OTP.");
        }
        db.prepare("UPDATE otp_codes SET attempts = ? WHERE id = ?").run(attempts, otpRow.id);
        throw httpError(401, `Incorrect OTP code. ${MAX_OTP_ATTEMPTS - attempts} attempt(s) left.`);
    }

    db.prepare("UPDATE otp_codes SET used = 1 WHERE id = ?").run(otpRow.id);
}

/** Forgot password, step 1: send a reset code. The reply never says whether the e-mail exists. */
export async function forgotPassword({ email }) {
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !EMAIL_RE.test(cleanEmail)) throw httpError(400, "Please enter a valid e-mail address.");
    const user = db.prepare("SELECT * FROM users WHERE lower(email) = ?").get(cleanEmail);
    const generic = { message: "If an account exists for this e-mail, a reset code has been sent. It expires in 5 minutes.", resendInSeconds: OTP_RESEND_SECONDS };
    if (!user) return generic;
    if (OTP_DELIVERY === "email" && !isEmailConfigured()) {
        throw httpError(503, "Password reset is unavailable: OTP_DELIVERY=email but e-mail (SMTP) is not configured.");
    }
    const r = await issueCode(user, "reset");
    return r.otpShownOnScreen ? r : { ...generic, resendInSeconds: r.resendInSeconds };
}

/** Forgot password, step 2: check the code, set the new password and sign out every session. */
export async function resetPassword({ email, code, newPassword }) {
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !code || !newPassword) throw httpError(400, "Email, code and new password are required.");
    const pwdError = validatePassword(newPassword);
    if (pwdError) throw httpError(400, pwdError);
    const user = db.prepare("SELECT * FROM users WHERE lower(email) = ?").get(cleanEmail);
    if (!user) throw httpError(401, "Invalid or expired code.");
    checkCode(user, code, "reset");
    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
    db.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ?").run(user.id);
    return { message: "Password changed. Please sign in with your new password." };
}

/** Change password while signed in (current password required); other sessions are signed out. */
export async function changePassword({ userId, sid, currentPassword, newPassword }) {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) throw httpError(404, "User not found.");
    if (!currentPassword || !(await bcrypt.compare(currentPassword, user.password_hash))) {
        throw httpError(401, "Current password is incorrect.");
    }
    const pwdError = validatePassword(newPassword);
    if (pwdError) throw httpError(400, pwdError);
    if (await bcrypt.compare(newPassword, user.password_hash)) throw httpError(400, "The new password must be different.");
    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
    db.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?").run(user.id, sid || "");
    return { message: "Password changed. Your other devices were signed out." };
}

/**
 * Step 2 of login: check the code and open a session.
 * @returns {{ token: string, user: object, expiresAt: string }}
 */
export function verifyOtp({ email, code, remember = false, userAgent, ip }) {
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail || !code) throw httpError(400, "Email and OTP code are required.");

    const user = db.prepare("SELECT * FROM users WHERE lower(email) = ?").get(cleanEmail);
    if (!user) throw httpError(401, "Invalid request.");

    checkCode(user, code, "login");

    const fresh = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    const { token, expiresAt } = createSession(fresh, { remember: !!remember, userAgent, ip });

    return {
        token,
        expiresAt,
        user: { id: fresh.id, name: fresh.name, email: fresh.email, organization: fresh.organization, role: fresh.role },
    };
}

/**
 * Validate a JWT and its session row. Returns the payload or throws.
 * Used by requireAuth on every API call.
 */
export function verifySessionToken(token) {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.sid) {
        const s = db.prepare("SELECT revoked, expires_at, last_seen_at FROM sessions WHERE id = ?").get(payload.sid);
        if (!s || s.revoked || new Date(s.expires_at) < new Date()) {
            throw Object.assign(new Error("Session ended"), { name: "SessionRevoked" });
        }
        // Touch last_seen at most once a minute
        if (Date.now() - new Date(s.last_seen_at.replace(" ", "T") + "Z").getTime() > 60000) {
            db.prepare("UPDATE sessions SET last_seen_at = datetime('now') WHERE id = ?").run(payload.sid);
        }
    }
    return payload;
}

/** Log out: revoke this session (or all of the user's sessions). */
export function revokeSession(payload, { all = false } = {}) {
    if (all) {
        db.prepare("UPDATE sessions SET revoked = 1 WHERE user_id = ?").run(payload.userId);
    } else if (payload.sid) {
        db.prepare("UPDATE sessions SET revoked = 1 WHERE id = ?").run(payload.sid);
    }
}

/** Active sessions of a user (for the "Signed-in devices" list). */
export function listSessions(userId) {
    return db.prepare(`
        SELECT id, remember, user_agent, ip, created_at, last_seen_at, expires_at
        FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ?
        ORDER BY last_seen_at DESC
    `).all(userId, new Date().toISOString());
}

/** Current user data for /api/auth/me. */
export function getUserById(userId) {
    return db.prepare(
        "SELECT id, name, email, organization, role, created_at FROM users WHERE id = ?"
    ).get(userId) || null;
}

export { JWT_SECRET };
