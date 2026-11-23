const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;
const COOKIE = "prodiesa_session";

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({ ok:false, error:"Método no permitido." });
  }

  if (!APPS_SCRIPT_URL) {
    return res.status(500).json({
      ok:false,
      error:"Vercel no tiene cargada la variable APPS_SCRIPT_URL en este deployment."
    });
  }

  try {
    const body = typeof req.body === "string"
      ? JSON.parse(req.body || "{}")
      : (req.body || {});

    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        ok:false,
        error:"Escribe usuario y contraseña."
      });
    }

    const r = await fetch(APPS_SCRIPT_URL, {
      method:"POST",
      redirect:"follow",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({
        action:"login",
        username,
        password
      })
    });

    const raw = await r.text();

    let payload;
    try {
      payload = JSON.parse(raw);
    } catch (_) {
      return res.status(502).json({
        ok:false,
        error:
          "Apps Script no devolvió JSON. HTTP " + r.status +
          ". Respuesta: " +
          raw.replace(/\s+/g," ").slice(0,180)
      });
    }

    if (payload?.ok !== true || !payload?.token) {
      return res.status(401).json({
        ok:false,
        error:payload?.error || "Usuario o contraseña incorrectos.",
        detail:payload?.detail || undefined
      });
    }

    const maxAge = Number(payload.expiresInSeconds || 28800);

    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=${encodeURIComponent(payload.token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
    );

    return res.status(200).json({
      ok:true,
      user:payload.user || username
    });

  } catch (err) {
    console.error("PRODIESA LOGIN ERROR:", err);

    return res.status(502).json({
      ok:false,
      error:"Vercel no pudo contactar Apps Script: " +
        String(err?.message || err)
    });
  }
};
