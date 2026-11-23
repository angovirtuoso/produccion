const {
  appsGet,
  credentialDigest,
  createSession,
  setSessionCookie,
  safeEqual
} = require("../lib/prodiesa-backend");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({ ok:false, error:"Método no permitido." });
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

    const { payload } = await appsGet("auth");

    if (payload?.ok !== true || !Array.isArray(payload.users)) {
      return res.status(502).json({
        ok:false,
        error:payload?.error || "No se pudo consultar la hoja Accesos."
      });
    }

    const target = username.toLowerCase();
    const row = payload.users.find(
      x => String(x.username || "").trim().toLowerCase() === target
    );

    const calculated = credentialDigest(username, password);
    const valid = row && safeEqual(calculated, row.credential);

    if (!valid) {
      return res.status(401).json({
        ok:false,
        error:"Usuario o contraseña incorrectos."
      });
    }

    const token = createSession(row.username);
    setSessionCookie(res, token);

    return res.status(200).json({
      ok:true,
      user:row.username
    });

  } catch (err) {
    return res.status(502).json({
      ok:false,
      error:String(err?.message || err)
    });
  }
};
