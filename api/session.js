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
    return res.status(401).json({ ok:false, auth:false });
  }

  try {
    const { payload } = await appsGet("auth");

    if (payload?.ok !== true || !Array.isArray(payload.users)) {
      // Error del backend: NO borrar una sesión válida.
      return res.status(503).json({
        ok:false,
        auth:true,
        user:session.u,
        error:payload?.error || "No se pudo validar Accesos."
      });
    }

    const active = payload.users.some(
      x => String(x.username || "").trim().toLowerCase() ===
           String(session.u || "").trim().toLowerCase()
    );

    if (!active) {
      clearSessionCookie(res);
      return res.status(401).json({
        ok:false,
        auth:false,
        error:"Usuario inactivo o inexistente."
      });
    }

    return res.status(200).json({
      ok:true,
      auth:true,
      user:session.u
    });

  } catch (err) {
    // Un fallo temporal de Google NO hace logout.
    return res.status(503).json({
      ok:false,
      auth:true,
      user:session.u,
      error:String(err?.message || err)
    });
  }
};
