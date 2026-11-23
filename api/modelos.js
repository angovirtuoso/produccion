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
    return res.status(405).json({ ok:false, error:"Método no permitido." });
  }

  const token = readCookie(req, COOKIE);

  if (!token) {
    return res.status(401).json({
      ok:false,
      auth:false,
      error:"No hay una sesión activa."
    });
  }

  if (!APPS_SCRIPT_URL) {
    return res.status(500).json({
      ok:false,
      error:"APPS_SCRIPT_URL no está cargada en Vercel."
    });
  }

  try {
    const r = await fetch(APPS_SCRIPT_URL, {
      method:"POST",
      redirect:"follow",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({ action:"models", token })
    });

    const raw = await r.text();
    let payload;

    try {
      payload = JSON.parse(raw);
    } catch (_) {
      return res.status(502).json({
        ok:false,
        error:
          "Apps Script no devolvió JSON al consultar ModelosLI. HTTP " +
          r.status + "."
      });
    }

    // SOLO una respuesta explícita auth:false invalida la sesión.
    // Un error de lectura, caché, permisos o datos de ModelosLI NO hace logout.
    if (payload?.auth === false) {
      res.setHeader(
        "Set-Cookie",
        `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      );

      return res.status(401).json({
        ok:false,
        auth:false,
        error:payload?.error || "Sesión inválida o vencida."
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
      error:
        "No se pudo consultar ModelosLI: " +
        String(err?.message || err)
    });
  }
};
