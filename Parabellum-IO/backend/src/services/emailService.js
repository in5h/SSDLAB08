/**
 * emailService.js — Sends OTP emails via Nodemailer
 * Configure EMAIL_USER and EMAIL_PASS in backend/.env
 *
 * For Gmail: enable 2-Step Verification at https://myaccount.google.com/security
 * Then create an App Password at https://myaccount.google.com/apppasswords
 * Use that 16-character App Password as EMAIL_PASS in .env
 */
import nodemailer from "nodemailer";

/** True when real SMTP credentials (not the .env.example placeholders) are configured. */
export function isEmailConfigured() {
    // EMAIL_AUTH=false: an internal SMTP relay that needs no login (only a host)
    if (process.env.EMAIL_AUTH === "false") return !!process.env.EMAIL_HOST;
    const user = process.env.EMAIL_USER || "";
    const pass = process.env.EMAIL_PASS || "";
    return !!(user && pass && !user.startsWith("your_") && !pass.startsWith("your_"));
}

const emailConfigured = isEmailConfigured();

if (emailConfigured) {
    console.log(`📧 Email service: SMTP configured (${process.env.EMAIL_USER || process.env.EMAIL_HOST})`);
} else {
    console.warn((process.env.OTP_DELIVERY || "").toLowerCase() === "email"
        ? "⚠️  Email service: SMTP not configured and OTP_DELIVERY=email — logins will fail until EMAIL_USER/EMAIL_PASS are set."
        : "ℹ️  Email service: SMTP not configured — login codes (OTP) are shown on the login screen.");
    console.warn("   Fill in EMAIL_USER and EMAIL_PASS in backend/.env to send the codes by e-mail.");
}

let transport = null;
function createTransport() {
    if (transport) return transport;
    const port = Number(process.env.EMAIL_PORT) || 587;
    transport = nodemailer.createTransport({
        host: process.env.EMAIL_HOST || "smtp.gmail.com",
        port,
        // Port 465 uses SSL from the start; 587/25 upgrade with STARTTLS
        secure: process.env.EMAIL_SECURE ? process.env.EMAIL_SECURE === "true" : port === 465,
        auth: (process.env.EMAIL_AUTH === "false") ? undefined : {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
        connectionTimeout: 15000,
    });
    return transport;
}

/** Check the SMTP login once at start-up so a wrong password shows up immediately in the log. */
export async function verifyEmailConfig() {
    if (!isEmailConfigured()) return { ok: false, reason: "not configured" };
    try {
        await createTransport().verify();
        console.log(`📧 SMTP connection OK (${process.env.EMAIL_HOST || "smtp.gmail.com"}:${process.env.EMAIL_PORT || 587})`);
        return { ok: true };
    } catch (err) {
        console.error(`❌ SMTP check failed: ${err.message}`);
        console.error("   For Gmail: turn on 2-Step Verification and use a 16-character App Password as EMAIL_PASS.");
        return { ok: false, reason: err.message };
    }
}

/**
 * Send OTP verification email.
 * @param {string} toEmail  - Recipient email
 * @param {string} name     - Recipient's display name
 * @param {string} code     - 6-digit OTP code
 */
export async function sendOtpEmail(toEmail, name, code, purpose = "login") {
    const what = purpose === "reset" ? "password reset code" : "login code";
    const fromName = "Parabellum IO";
    const fromEmail = process.env.EMAIL_FROM || process.env.EMAIL_USER || "noreply@parabellum.io";

    const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: Inter, -apple-system, sans-serif; background: #0b1220; color: #e6eef8; margin: 0; padding: 0; }
    .container { max-width: 480px; margin: 40px auto; background: #0f1724; border-radius: 16px; overflow: hidden; border: 1px solid rgba(255,255,255,0.06); }
    .header { background: linear-gradient(135deg, #1e40af, #2563eb); padding: 32px; text-align: center; }
    .header h1 { margin: 0; font-size: 22px; color: #fff; letter-spacing: -0.5px; }
    .header p  { margin: 6px 0 0; color: rgba(255,255,255,0.7); font-size: 13px; }
    .body   { padding: 32px; text-align: center; }
    .body p { color: #94a3b8; margin: 0 0 24px; line-height: 1.6; }
    .otp-box { display: inline-block; background: rgba(37,99,235,0.12); border: 2px solid #2563eb; border-radius: 12px; padding: 16px 40px; margin: 4px 0 28px; }
    .otp-code { font-size: 40px; font-weight: 800; letter-spacing: 10px; color: #60a5fa; font-family: monospace; }
    .timer { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.3); border-radius: 8px; padding: 10px 16px; color: #f87171; font-size: 13px; margin-bottom: 24px; }
    .footer { padding: 20px 32px; text-align: center; border-top: 1px solid rgba(255,255,255,0.05); color: #475569; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Parabellum IO</h1>
      <p>DevSecOps Platform — Login Verification</p>
    </div>
    <div class="body">
      <p>Hello <strong style="color:#e6eef8">${name}</strong>,<br>
      Here is your one-time login code:</p>
      <div class="otp-box">
        <div class="otp-code">${code}</div>
      </div>
      <div class="timer">
        ⏱ This code expires in <strong>5 minutes</strong>.
        Do not share it with anyone.
      </div>
      <p style="font-size:13px">If you did not request this, please ignore this email or change your password immediately.</p>
    </div>
    <div class="footer">
      © ${new Date().getFullYear()} Parabellum IO · Secure DevSecOps Platform
    </div>
  </div>
</body>
</html>`;

    // Dev mode: SMTP not configured — print code to console
    if (!isEmailConfigured()) {
        console.log(`\n${"=".repeat(52)}`);
        console.log(`📧 OTP CODE  (SMTP not configured — dev mode)`);
        console.log(`   To:   ${toEmail}`);
        console.log(`   Name: ${name}`);
        console.log(`   Code: \x1b[1;33m${code}\x1b[0m   (expires in 5 minutes)`);
        console.log(`${"=".repeat(52)}\n`);
        return;
    }

    // Production: send via SMTP
    try {
        const transport = createTransport();
        await transport.sendMail({
            from: `"${fromName}" <${fromEmail}>`,
            to: toEmail,
            subject: `${code} — Your Parabellum IO ${what}`,
            text: `Hello ${name},\n\nYour Parabellum IO ${what} is ${code}.\nIt expires in 5 minutes. Do not share it with anyone.\n\nIf you did not try to log in, change your password.`,
            html,
        });
        console.log(`📧 OTP sent successfully to ${toEmail}`);
    } catch (err) {
        console.error(`❌ SMTP error sending OTP to ${toEmail}:`, err.message);
        throw Object.assign(
            new Error(`Could not send OTP email: ${err.message}. Check EMAIL_USER / EMAIL_PASS in .env.`),
            { status: 502 }
        );
    }
}
