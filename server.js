require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const tls = require("tls");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

// Indispensable pour Vercel (pour que l'anti-spam lise les vraies IP)
app.set("trust proxy", 1);

/* ================================
   CONFIGURATIONS EMAIL
================================ */
const SSL_TIMEOUT_MS = 8000;
const SMTP_HOST = process.env.EMAIL_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.EMAIL_PORT || 465);
const SMTP_SECURE = String(process.env.EMAIL_SECURE || "true") === "true";
const SMTP_USER = process.env.EMAIL_USER || "";
const SMTP_PASS = process.env.EMAIL_PASS || "";
const CONTACT_TO = process.env.CONTACT_TO || "";
const CONTACT_FROM = process.env.CONTACT_FROM || SMTP_USER || CONTACT_TO;

/* ================================
   SÉCURITÉ & MIDDLEWARES
================================ */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));

// LIGNE CORRIGÉE : On sert TOUJOURS le dossier public, même sur Vercel
app.use(express.static(path.join(__dirname, "public")));

/* ================================
   ANTI-SPAM
================================ */
const sslLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 30, 
  message: { code: "TOO_MANY_REQUESTS", message: "Trop de requêtes. Veuillez patienter une minute." }
});

const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { code: "TOO_MANY_REQUESTS", message: "Limite de messages atteinte. Réessayez plus tard." }
});

/* ================================
   UTILS
================================ */
function normalizeDomain(input) {
  if (!input || typeof input !== "string") return null;
  let value = input.trim().replace(/^https?:\/\//i, "").split("/")[0].replace(/:\d+$/, "").toLowerCase();
  if (!value) return null;
  const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
  const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
  if (!isDomain && !isIPv4) return null;
  return value;
}

function getSeverity(daysLeft) {
  if (daysLeft < 7) return "bad";
  if (daysLeft < 30) return "warn";
  return "ok";
}

function mapSslError(error) {
  const code = error?.code || error?.message || "SSL_CHECK_FAILED";
  if (code === "INVALID_DOMAIN") return { http: 400, body: { code: "INVALID", message: "Invalid domain." } };
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENOTDIR") return { http: 404, body: { code: "NOT_FOUND", message: "Domain not found." } };
  if (code === "ECONNREFUSED" || code === "NO_CERTIFICATE") return { http: 400, body: { code: "NO_TLS", message: "No TLS certificate." } };
  if (code === "TIMEOUT" || code === "ETIMEDOUT") return { http: 504, body: { code: "TIMEOUT", message: "Timeout." } };
  return { http: 500, body: { code: "CHECK_FAILED", message: "Analysis failed." } };
}

function sanitizeText(str) {
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ================================
   API : VERIFICATION SSL
================================ */
app.post("/api/ssl-check", sslLimiter, async (req, res) => {
  const domain = normalizeDomain(req.body.input || req.body.domain || req.body.url);
  if (!domain) return res.status(400).json({ code: "INVALID", message: "Invalid domain." });

  try {
    const result = await new Promise((resolve, reject) => {
      const socket = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false }, () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (!cert || !cert.valid_to) throw new Error("NO_CERTIFICATE");
          
          const expDate = new Date(cert.valid_to);
          if (Number.isNaN(expDate.getTime())) throw new Error("NO_CERTIFICATE");
          
          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const now = new Date();
          const diffMs = expDate.getTime() - now.getTime();
          const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
          
          let issuer = typeof cert.issuer === "string" ? cert.issuer : (cert.issuer?.O || cert.issuer?.CN || "Unknown");

          socket.end();
          resolve({
            domain, expiresAt: expDate.toISOString(),
            validFrom: validFrom && !Number.isNaN(validFrom.getTime()) ? validFrom.toISOString() : null,
            issuer, daysLeft, severity: getSeverity(daysLeft)
          });
        } catch (err) { socket.destroy(); reject(err); }
      });
      socket.setTimeout(SSL_TIMEOUT_MS);
      socket.on("timeout", () => { socket.destroy(); reject(Object.assign(new Error("TIMEOUT"), { code: "TIMEOUT" })); });
      socket.on("error", (error) => reject(error));
    });
    return res.status(200).json(result);
  } catch (error) {
    const mapped = mapSslError(error);
    return res.status(mapped.http).json(mapped.body);
  }
});

/* ================================
   API : FORMULAIRE DE CONTACT
================================ */
const transporter = nodemailer.createTransport({
  host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE,
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

app.post("/api/contact", contactLimiter, async (req, res) => {
  const name = sanitizeText(String(req.body.name || "").trim());
  const email = sanitizeText(String(req.body.email || "").trim());
  const subject = sanitizeText(String(req.body.subject || "").trim());
  const message = sanitizeText(String(req.body.message || "").trim());

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Adresse email invalide." });
  if (!message || message.length < 2) return res.status(400).json({ message: "Le message est requis." });

  if (!SMTP_USER || !SMTP_PASS) {
    return res.status(500).json({ message: "Le serveur mail n'est pas configuré sur Vercel." });
  }

  try {
    await transporter.sendMail({
      from: CONTACT_FROM, to: CONTACT_TO, replyTo: email,
      subject: subject ? `[SEAL Contact] ${subject}` : "[SEAL Contact] Nouveau message",
      text: `Nouveau message reçu via SEAL\n\nNom: ${name}\nEmail: ${email}\nSujet: ${subject}\n\nMessage:\n${message}\n`,
    });
    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error("[SEAL ERREUR] Échec de l'envoi :", error);
    return res.status(502).json({ message: "Erreur lors de l'envoi de l'email." });
  }
});

/* ================================
   ROUTAGE DES PAGES HTML
================================ */
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "SEAL_page_accueil.html"));
});

// Capture les erreurs 404 de l'API
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "Route API introuvable." });
});

// Capture les erreurs 404 globales (si une page HTML n'existe pas)
app.use((_req, res) => {
  res.status(404).send("404 - Page introuvable");
});

/* ================================
   DÉMARRAGE & EXPORT VERCEL
================================ */
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`[OK] Serveur SEAL démarré en local sur le port ${PORT}`);
  });
}

// CRUCIAL POUR VERCEL
module.exports = app;