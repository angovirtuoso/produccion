const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL || "https://script.google.com/macros/s/AKfycbzK90whpc-rNz3QVRuW0aaKMSEgebGV0zCKQy2B3TJWte7Jgyi1xWeiVtL2qEVm01n15A/exec";
const COOKIE = "prodiesa_session";

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control","no-store");

  if(req.method !== "POST") {
    res.status(405).json({ok:false,error:"Método no permitido."});
    return;
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if(!username || !password) {
      res.status(400).json({ok:false,error:"Escribe usuario y contraseña."});
      return;
    }

    const r = await fetch(APPS_SCRIPT_URL,{
      method:"POST",
      redirect:"follow",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({action:"login",username,password})
    });

    const payload = await r.json();

    if(payload?.ok !== true || !payload?.token) {
      res.status(401).json({ok:false,error:payload?.error || "Usuario o contraseña incorrectos."});
      return;
    }

    const maxAge = Number(payload.expiresInSeconds || 28800);
    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=${encodeURIComponent(payload.token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
    );

    res.status(200).json({ok:true,user:payload.user || username});
  } catch(err) {
    res.status(502).json({ok:false,error:"No se pudo validar el acceso."});
  }
};
