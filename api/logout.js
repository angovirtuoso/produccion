const COOKIE = "prodiesa_session";

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control","no-store");

  if (req.method !== "POST") {
    return res.status(405).json({ ok:false });
  }

  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  );

  return res.status(200).json({ ok:true });
};
