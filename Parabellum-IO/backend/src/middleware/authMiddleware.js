/**
 * authMiddleware.js — JWT + session verification middleware
 * Attaches decoded user to req.user on success.
 * All /api routes except /api/auth/* require a valid token.
 */
import { verifySessionToken } from "../services/authService.js";

export function requireAuth(req, res, next) {
    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
        return res.status(401).json({
            error: "Authentication required. Please log in.",
            redirect: "/login",
        });
    }

    try {
        req.user = verifySessionToken(token);
        next();
    } catch (err) {
        const message =
            err.name === "TokenExpiredError" ? "Session expired. Please log in again." :
            err.name === "SessionRevoked" ? "You have been logged out. Please log in again." :
            "Invalid token. Please log in.";
        return res.status(401).json({ error: message, redirect: "/login" });
    }
}
