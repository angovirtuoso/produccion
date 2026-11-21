const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL || "https://script.google.com/macros/s/AKfycbzK90whpc-rNz3QVRuW0aaKMSEgebGV0zCKQy2B3TJWte7Jgyi1xWeiVtL2qEVm01n15A/exec";
const COOKIE = "prodiesa_session";

function readCookie(req,name){
  const raw = String(req.headers.cookie || "");
  for(const part of raw.split(";")){
    const [k,...rest] = part.trim().split("=");
    if(k === name) return decodeURIComponent(rest.join("=") || "");
  }
  return "";
}

module.exports = async function handler(req,res){
  res.setHeader("Cache-Control","no-store");

  if(req.method !== "GET") {
    res.status(405).json({ok:false});
    return;
  }

  const token = readCookie(req,COOKIE);
  if(!token) {
    res.status(401).json({ok:false,auth:false});
    return;
  }

  try {
    const r = await fetch(APPS_SCRIPT_URL,{
      method:"POST",
      redirect:"follow",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({action:"session",token})
    });

    const payload = await r.json();

    if(payload?.ok !== true || payload?.auth !== true) {
      res.setHeader("Set-Cookie",`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      res.status(401).json({ok:false,auth:false});
      return;
    }

    res.status(200).json({ok:true,auth:true,user:payload.user || ""});
  } catch(err) {
    res.status(502).json({ok:false,error:"Backend no disponible."});
  }
};
