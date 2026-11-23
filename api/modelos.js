const {
  appsGet,
  verifySession,
  readCookie,
  clearSessionCookie
} = require("../lib/prodiesa-backend");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    return res.status(405).json({ ok:false });
  }

  const session = verifySession(readCookie(req));

  if (!session) {
    clearSessionCookie(res);
    return res.status(401).json({
      ok:false,
      auth:false,
      error:"Sesión inválida o vencida."
    });
  }

  try {
    const { payload } = await appsGet("models", session.u);

    if (payload?.auth === false) {
      clearSessionCookie(res);
      return res.status(401).json({
        ok:false,
        auth:false,
        error:payload?.error || "Usuario inactivo."
      });
    }

    if (payload?.ok !== true) {
      return res.status(502).json({
        ok:false,
        auth:true,
        error:payload?.error || "No se pudo leer ModelosLI.",
        detail:payload?.detail || undefined
      });
    }

    return res.status(200).json(payload);

  } catch (err) {
    return res.status(502).json({
      ok:false,
      auth:true,
      error:String(err?.message || err)
    });
  }
};
