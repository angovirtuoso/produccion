const crypto = require("crypto");

const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;
const BACKEND_SECRET = process.env.PRODIESA_BACKEND_SECRET;
const COOKIE = "prodiesa_session";
const SESSION_SECONDS = 8 * 60 * 60;

function base64url(input) {
  return Buffer.from(input).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function hmac(value) {
  return crypto.createHmac("sha256", BACKEND_SECRET)
    .update(String(value), "utf8")
    .digest("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function signedUrl(action, user = "") {
  if (!APPS_SCRIPT_URL) throw new Error("Falta APPS_SCRIPT_URL en Vercel.");
  if (!BACKEND_SECRET) throw new Error("Falta PRODIESA_BACKEND_SECRET en Vercel.");

  const ts = String(Date.now());
  const nonce = crypto.randomBytes(16).toString("hex");
  const cleanUser = String(user || "").trim();
  const canonical = [action, ts, nonce, cleanUser].join("\n");
  const sig = hmac(canonical);

  const u = new URL(APPS_SCRIPT_URL);
  u.searchParams.set("action", action);
  u.searchParams.set("ts", ts);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("sig", sig);
  if (cleanUser) u.searchParams.set("user", cleanUser);

  return u.toString();
}

async function appsGet(action, user = "") {
  let lastError = null;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(signedUrl(action, user), {
        method: "GET",
        redirect: "follow",
        cache: "no-store"
      });

      const raw = await r.text();
      let payload;

      try {
        payload = JSON.parse(raw);
      } catch (_) {
        throw new Error(
          `Apps Script no devolvió JSON. HTTP ${r.status}. ` +
          raw.replace(/\s+/g, " ").slice(0, 160)
        );
      }

      return { status: r.status, payload };

    } catch (err) {
      lastError = err;
      if (attempt < 3) {
        await new Promise(resolve => setTimeout(resolve, 250 * attempt));
      }
    }
  }

  throw lastError || new Error("No se pudo contactar Apps Script.");
}

function credentialDigest(username, password) {
  return hmac(
    "cred\n" +
    String(username || "").trim().toLowerCase() +
    "\n" +
    String(password || "")
  );
}

function createSession(username) {
  const now = Date.now();
  const payload = {
    u: String(username),
    iat: now,
    exp: now + SESSION_SECONDS * 1000
  };

  const body = base64url(JSON.stringify(payload));
  const sig = hmac("session\n" + body);
  return body + "." + sig;
}

function verifySession(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 2) return null;

  const body = parts[0];
  const sig = parts[1];

  if (!safeEqual(hmac("session\n" + body), sig)) return null;

  try {
    let normalized = body.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4) normalized += "=";

    const payload = JSON.parse(
      Buffer.from(normalized, "base64").toString("utf8")
    );

    if (!payload.u || !payload.exp || Date.now() >= Number(payload.exp)) {
      return null;
    }

    return payload;
  } catch (_) {
    return null;
  }
}

function readCookie(req, name = COOKIE) {
  const raw = String(req.headers.cookie || "");

  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("=") || "");
  }

  return "";
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  );
}

module.exports = {
  appsGet,
  credentialDigest,
  createSession,
  verifySession,
  readCookie,
  setSessionCookie,
  clearSessionCookie,
  safeEqual
};
