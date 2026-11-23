const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;
const COOKIE = "prodiesa_session";

function readCookie(req, name) {
  const raw = String(req.headers.cookie || "");
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("=") || "");
  }
  return "";
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({ ok:false });
  }

  const token = readCookie(req, COOKIE);
  if (!token) {
    return res.status(401).json({ ok:false, auth:false });
  }

  if (!APPS_SCRIPT_URL) {
    return res.status(500).json({
      ok:false,
      auth:false,
      error:"APPS_SCRIPT_URL no está cargada en Vercel."
    });
  }

  try {
    const r = await fetch(APPS_SCRIPT_URL, {
      method:"POST",
      redirect:"follow",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({ action:"session", token })
    });

    const raw = await r.text();
    let payload;

    try {
      payload = JSON.parse(raw);
    } catch (_) {
      return res.status(502).json({
        ok:false,
        auth:false,
        error:"Apps Script no devolvió JSON. HTTP " + r.status
      });
    }

    if (payload?.ok !== true || payload?.auth !== true) {
      res.setHeader(
        "Set-Cookie",
        `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      );
      return res.status(401).json({ ok:false, auth:false });
    }

    return res.status(200).json({
      ok:true,
      auth:true,
      user:payload.user || ""
    });

  } catch (err) {
    return res.status(502).json({
      ok:false,
      auth:false,
      error:"No se pudo contactar Apps Script."
    });
  }
};
