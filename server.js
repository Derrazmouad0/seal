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

// Indispensable pour Vercel : permet aux limites anti-spam de lire la vraie adresse IP du visiteur
app.set("trust proxy", 1);

/*
================================
CONFIGURATIONS
================================
*/
const SSL_TIMEOUT_MS = 8000;
const SMTP_HOST = process.env.EMAIL_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.EMAIL_PORT || 465);
const SMTP_SECURE = String(process.env.EMAIL_SECURE || "true") === "true";
const SMTP_USER = process.env.EMAIL_USER || "";
const SMTP_PASS = process.env.EMAIL_PASS || "";
const CONTACT_TO = process.env.CONTACT_TO || "";
const CONTACT_FROM = process.env.CONTACT_FROM || SMTP_USER || CONTACT_TO;

/*
================================
SÉCURITÉ & MIDDLEWARES
================================
*/
// Helmet protège les en-têtes HTTP (désactivé pour CSP afin d'autoriser tes scripts HTML internes)
app.use(helmet({ contentSecurityPolicy: false }));

// CORS : Autoriser les requêtes
app.use(cors({
  origin: '*', // Sur Vercel, tu pourras remplacer '*' par ton vrai domaine plus tard
  methods: ['GET', 'POST']
}));

app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));

// Sert les fichiers statiques (surtout utile en local, Vercel gère ça via vercel.json en prod)
app.use(express.static(path.join(__dirname, "public")));

/*
================================
LIMITATIONS DE REQUÊTES (ANTI-SPAM)
================================
*/
// Limite pour le scanner SSL : max 30 requêtes par minute par IP
const sslLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 30, 
  message: { code: "TOO_MANY_REQUESTS", message: "Trop de requêtes. Veuillez patienter une minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Limite pour le formulaire de contact : max 3 messages par heure par IP
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { code: "TOO_MANY_REQUESTS", message: "Vous avez atteint la limite de messages. Réessayez plus tard." },
  standardHeaders: true,
  legacyHeaders: false,
});

/*
================================
FONCTIONS UTILITAIRES
================================
*/
function normalizeDomain(input) {
  if (!input || typeof input !== "string") return null;

  let value = input.trim();
  if (!value) return null;

  value = value.replace(/^https?:\/\//i, "");
  value = value.split("/")[0];
  value = value.replace(/:\d+$/, "");
  value = value.toLowerCase();

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
  const code = error && error.code ? error.code : error && error.message ? error.message : "SSL_CHECK_FAILED";

  if (code === "INVALID_DOMAIN") return { http: 400, body: { code: "INVALID", message: "Invalid domain." } };
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "ENOTDIR") return { http: 404, body: { code: "NOT_FOUND", message: "Website not found or domain does not exist." } };
  if (code === "ECONNREFUSED") return { http: 400, body: { code: "NO_TLS", message: "No TLS certificate detected." } };
  if (code === "TIMEOUT" || code === "ETIMEDOUT") return { http: 504, body: { code: "TIMEOUT", message: "Timeout while checking SSL." } };
  if (code === "NO_CERTIFICATE") return { http: 400, body: { code: "NO_TLS", message: "No TLS certificate detected." } };

  return { http: 500, body: { code: "CHECK_FAILED", message: "Unable to analyze this domain right now." } };
}

// Nettoyage basique pour éviter l'injection de code XSS dans les emails
function sanitizeText(str) {
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/*
================================
VERIFICATION SSL API
================================
*/
function checkSSL(domain) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false, // Permet de lire même les certificats expirés
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);

          if (!cert || Object.keys(cert).length === 0 || !cert.valid_to) {
            socket.destroy();
            reject(Object.assign(new Error("NO_CERTIFICATE"), { code: "NO_CERTIFICATE" }));
            return;
          }

          const expirationDate = new Date(cert.valid_to);
          const validFromDate = cert.valid_from ? new Date(cert.valid_from) : null;

          if (Number.isNaN(expirationDate.getTime())) {
            socket.destroy();
            reject(Object.assign(new Error("NO_CERTIFICATE"), { code: "NO_CERTIFICATE" }));
            return;
          }

          const now = new Date();
          const diffMs = expirationDate.getTime() - now.getTime();
          const daysLeft = Math.floor(diffMs / (1000 * 60 * 60 * 24));
          const severity = getSeverity(daysLeft);

          let issuer = "Unknown";
          if (cert.issuer) {
            if (typeof cert.issuer === "string") {
              issuer = cert.issuer;
            } else {
              issuer = cert.issuer.O || cert.issuer.CN || "Unknown";
            }
          }

          socket.end();

          resolve({
            domain,
            expiresAt: expirationDate.toISOString(),
            validFrom: validFromDate && !Number.isNaN(validFromDate.getTime()) ? validFromDate.toISOString() : null,
            validTo: expirationDate.toISOString(),
            issuer,
            daysLeft,
            msLeft: diffMs,
            severity,
          });
        } catch (error) {
          socket.destroy();
          reject(error);
        }
      }
    );

    socket.setTimeout(SSL_TIMEOUT_MS);

    socket.on("timeout", () => {
      socket.destroy();
      reject(Object.assign(new Error("TIMEOUT"), { code: "TIMEOUT" }));
    });

    socket.on("error", (error) => {
      reject(error);
    });
  });
}

app.post("/api/ssl-check", sslLimiter, async (req, res) => {
  const rawInput = req.body.input || req.body.domain || req.body.url;
  const domain = normalizeDomain(rawInput);

  if (!domain) {
    return res.status(400).json({ code: "INVALID", message: "Invalid domain." });
  }

  try {
    const result = await checkSSL(domain);
    return res.status(200).json(result);
  } catch (error) {
    const mapped = mapSslError(error);
    return res.status(mapped.http).json(mapped.body);
  }
});

/*
================================
FORMULAIRE CONTACT API
================================
*/
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

app.post("/api/contact", contactLimiter, async (req, res) => {
  const name = sanitizeText(String(req.body.name || "").trim());
  const email = sanitizeText(String(req.body.email || "").trim());
  const subject = sanitizeText(String(req.body.subject || "").trim());
  const message = sanitizeText(String(req.body.message || "").trim());

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ code: "INVALID", message: "Invalid email." });
  }

  if (!message || message.length < 2) {
    return res.status(400).json({ code: "INVALID", message: "Message is required." });
  }

  if (!SMTP_USER || !SMTP_PASS || !CONTACT_TO) {
    console.error("[SEAL] ERREUR : Serveur SMTP non configuré dans les variables d'environnement Vercel.");
    return res.status(500).json({ code: "MAIL_NOT_CONFIGURED", message: "Le serveur mail n'est pas configuré." });
  }

  try {
    await transporter.sendMail({
      from: CONTACT_FROM,
      to: CONTACT_TO,
      replyTo: email,
      subject: subject ? `[SEAL Contact] ${subject}` : "[SEAL Contact] Nouveau message",
      text:
        `Nouveau message reçu via le formulaire de contact SEAL\n\n` +
        `Nom: ${name || "(Non fourni)"}\n` +
        `Email: ${email}\n` +
        `Sujet: ${subject || "(Non fourni)"}\n\n` +
        `Message:\n${message}\n`,
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error("[SEAL] Erreur d'envoi d'email:", error);
    return res.status(502).json({ code: "MAIL_FAILED", message: "Échec de l'envoi de l'email via le fournisseur." });
  }
});

/*
================================
ROUTES HTML & FALLBACK
================================
*/
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "SEAL_page_accueil.html"));
});

app.use("/api", (_req, res) => {
  return res.status(404).json({ code: "NOT_FOUND", message: "API route not found." });
});

app.use((_req, res) => {
  res.status(404).send("404 - Page introuvable");
});

/*
================================
DÉMARRAGE DU SERVEUR & EXPORT VERCEL
================================
*/

// Ne lance le serveur sur un port que si on teste en local sur son PC. 
// Sur Vercel, c'est l'export module.exports = app qui fait le travail.
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`[OK] Serveur SEAL en ligne (Mode Local) sur http://localhost:${PORT}`);
  });
}

// LIGNE CRUCIALE POUR VERCEL : On exporte l'application
module.exports = app;