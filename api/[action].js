// One serverless function for: /api/login /api/callback /api/me /api/logout /api/status /api/apply
const crypto = require('crypto');
const E = process.env;

const sign = s => crypto.createHmac('sha256', E.SESSION_SECRET).update(s).digest('base64url');
const parse = h => Object.fromEntries((h || '').split(/;\s*/).filter(Boolean).map(c => {
  const i = c.indexOf('=');
  return [c.slice(0, i), c.slice(i + 1)];
}));
const setCookie = (res, n, v, age) => res.setHeader('Set-Cookie',
  [].concat(res.getHeader('Set-Cookie') || [], `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`));

function readSession(req) {
  const [p, s] = (parse(req.headers.cookie).sess || '').split('.');
  if (!p || !s) return null;
  const good = Buffer.from(sign(p));
  if (s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), good)) return null;
  const d = JSON.parse(Buffer.from(p, 'base64url'));
  return d.exp > Date.now() ? d : null;
}

const discord = (path, token) =>
  fetch('https://discord.com/api' + path, { headers: { Authorization: 'Bearer ' + token } });

const routes = {
  login(req, res) {
    const state = crypto.randomBytes(16).toString('hex');
    setCookie(res, 'st', state, 600);
    const q = new URLSearchParams({
      client_id: E.DISCORD_CLIENT_ID, response_type: 'code', state,
      scope: 'identify', // Minimized scope since we aren't checking guild roles anymore
      redirect_uri: E.SITE_URL + '/api/callback',
    });
    res.redirect('https://discord.com/oauth2/authorize?' + q);
  },

  async callback(req, res) {
    const { code, state } = req.query;
    if (!code || state !== parse(req.headers.cookie).st) return res.redirect('/?login=failed');
    const t = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: E.DISCORD_CLIENT_ID, client_secret: E.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code', code, redirect_uri: E.SITE_URL + '/api/callback',
      }),
    }).then(r => r.json());
    if (!t.access_token) return res.redirect('/?login=failed');

    const u = await discord('/users/@me', t.access_token).then(r => r.json());
    
    // Bypassed role/guild checks: Everyone logging in is marked as whitelisted/inGuild for direct IP viewing
    const d = {
      id: u.id, name: u.global_name || u.username,
      inGuild: true,
      whitelisted: true,
      exp: Date.now() + 864e5, // 24h
    };
    const p = Buffer.from(JSON.stringify(d)).toString('base64url');
    setCookie(res, 'sess', `${p}.${sign(p)}`, 86400);
    setCookie(res, 'st', '', 0);
    res.redirect('/#whitelist');
  },

  me(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    const s = readSession(req);
    if (!s) return res.json({ loggedIn: false });
    res.json({
      loggedIn: true, name: s.name, inGuild: true, whitelisted: true,
      ip: E.SERVER_IP, bedrockPort: E.BEDROCK_PORT || '19132',
    });
  },

  logout(req, res) {
    setCookie(res, 'sess', '', 0);
    res.redirect('/');
  },

  async status(req, res) {
    res.setHeader('Cache-Control', 's-maxage=60');
    if (!E.SERVER_IP) return res.json({ online: false });
    try {
      const s = await fetch('https://api.mcsrvstat.us/3/' + E.SERVER_IP).then(r => r.json());
      res.json({ online: !!s.online, players: s.players?.online || 0, max: s.players?.max || 0 });
    } catch { res.json({ online: false }); }
  },

  async apply(req, res) {
    // Disabled since you are managing applications/whitelisting manually
    res.status(501).json({ error: 'Not implemented' });
  },
};

module.exports = async (req, res) => {
  const name = req.query.action;
  if (!Object.hasOwn(routes, name)) return res.status(404).end();
  try { await routes[name](req, res); }
  catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
};
