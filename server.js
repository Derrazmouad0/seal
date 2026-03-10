require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const nodemailer = require("nodemailer");
const tls = require("tls");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

/*
================================
CONFIG
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
MIDDLEWARES
================================
*/

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/*
================================
HEALTH CHECK
================================
*/

app.get("/healthz", (_req, res) => {
  res.status(200).send("ok");
});

/*
================================
UTILS
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

  // Vérification basique domaine / sous-domaine / IP
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

  if (code === "INVALID_DOMAIN") {
    return {
      http: 400,
      body: {
        code: "INVALID",
        message: "Invalid domain.",
      },
    };
  }

  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return {
      http: 404,
      body: {
        code: "NOT_FOUND",
        message: "Website not found or domain does not exist.",
      },
    };
  }

  if (code === "ECONNREFUSED") {
    return {
      http: 400,
      body: {
        code: "NO_TLS",
        message: "No TLS certificate detected.",
      },
    };
  }

  if (code === "TIMEOUT" || code === "ETIMEDOUT") {
    return {
      http: 504,
      body: {
        code: "TIMEOUT",
        message: "Timeout while checking SSL.",
      },
    };
  }

  if (code === "NO_CERTIFICATE") {
    return {
      http: 400,
      body: {
        code: "NO_TLS",
        message: "No TLS certificate detected.",
      },
    };
  }

  return {
    http: 500,
    body: {
      code: "CHECK_FAILED",
      message: "Unable to analyze this domain right now.",
    },
  };
}

/*
================================
VERIFICATION SSL
================================
*/

function checkSSL(domain) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);

          if (!cert || Object.keys(cert).length === 0 || !cert.valid_to) {
            socket.end();
            reject(Object.assign(new Error("NO_CERTIFICATE"), { code: "NO_CERTIFICATE" }));
            return;
          }

          const expirationDate = new Date(cert.valid_to);
          const validFromDate = cert.valid_from ? new Date(cert.valid_from) : null;

          if (Number.isNaN(expirationDate.getTime())) {
            socket.end();
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
            validFrom: validFromDate && !Number.isNaN(validFromDate.getTime())
              ? validFromDate.toISOString()
              : null,
            validTo: expirationDate.toISOString(),
            issuer,
            daysLeft,
            msLeft: diffMs,
            severity,
          });
        } catch (error) {
          socket.end();
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

app.post("/api/ssl-check", async (req, res) => {
  const rawInput = req.body.input || req.body.domain || req.body.url;
  const domain = normalizeDomain(rawInput);

  if (!domain) {
    return res.status(400).json({
      code: "INVALID",
      message: "Invalid domain.",
    });
  }

  try {
    const result = await checkSSL(domain);
    return res.status(200).json(result);
  } catch (error) {
    console.error("SSL check error:", error);
    const mapped = mapSslError(error);
    return res.status(mapped.http).json(mapped.body);
  }
});

/*
================================
FORMULAIRE CONTACT
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

app.post("/api/contact", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim();
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      code: "INVALID",
      message: "Invalid email.",
    });
  }

  if (!message || message.length < 2) {
    return res.status(400).json({
      code: "INVALID",
      message: "Message is required.",
    });
  }

  if (!SMTP_USER || !SMTP_PASS || !CONTACT_TO) {
    return res.status(500).json({
      code: "MAIL_NOT_CONFIGURED",
      message: "Email service is not configured on the server.",
    });
  }

  try {
    await transporter.sendMail({
      from: CONTACT_FROM,
      to: CONTACT_TO,
      replyTo: email,
      subject: subject ? `[SEAL Contact] ${subject}` : "[SEAL Contact] New message",
      text:
        `New message from SEAL contact form\n\n` +
        `Name: ${name || "(not provided)"}\n` +
        `Email: ${email}\n` +
        `Subject: ${subject || "(not provided)"}\n\n` +
        `Message:\n${message}\n`,
    });

    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error("Mail error:", error);
    return res.status(502).json({
      code: "MAIL_FAILED",
      message: "Failed to send email.",
    });
  }
});

/*
================================
ROUTES HTML
================================
*/

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "SEAL_page_accueil.html"));
});

/*
================================
404 API
================================
*/

app.use("/api", (_req, res) => {
  return res.status(404).json({
    code: "NOT_FOUND",
    message: "API route not found.",
  });
});

/*
================================
404 GENERAL
================================
*/

app.use((_req, res) => {
  res.status(404).send("404 - Page not found");
});

/*
================================
START SERVER
================================
*/

app.listen(PORT, () => {
  console.log(`SEAL server running on http://localhost:${PORT}`);
});