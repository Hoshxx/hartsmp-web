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
      scope: 'identify guilds.members.read',
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
    const m = await discord(`/users/@me/guilds/${E.DISCORD_GUILD_ID}/member`, t.access_token);
    const member = m.ok ? await m.json() : null;
    const d = {
      id: u.id, name: u.global_name || u.username,
      inGuild: !!member,
      whitelisted: !!member && member.roles.includes(E.WHITELIST_ROLE_ID),
      exp: Date.now() + 864e5, // 24h; log in again to refresh role status
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
      loggedIn: true, name: s.name, inGuild: s.inGuild, whitelisted: s.whitelisted,
      // The address is only ever sent to whitelisted members
      ...(s.whitelisted && { ip: E.SERVER_IP, bedrockPort: E.BEDROCK_PORT || '19132' }),
    });
  },

  logout(req, res) {
    setCookie(res, 'sess', '', 0);
    res.redirect('/');
  },

  async status(req, res) {
    res.setHeader('Cache-Control', 's-maxage=60');
    const addr = E.STATUS_ADDRESS || E.SERVER_IP; // include the port if it isn't 25565, e.g. host:25567
    if (!addr) return res.json({ online: false });
    try {
      const s = await fetch('https://api.mcsrvstat.us/3/' + addr).then(r => r.json());
      res.json({ online: !!s.online, players: s.players?.online || 0, max: s.players?.max || 0 });
    } catch { res.json({ online: false }); }
  },

  // Proxies BlueMap through Vercel: HTTPS for the browser, login required, server IP stays in an env var
  async bluemap(req, res) {
    const s = readSession(req);
    if (!s || !s.whitelisted) return res.status(401).send('Whitelisted members only');
    if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).end();
    const path = [].concat(req.query.path || []).join('/').replace(/^\/+/, '');
    if (path.split('/').includes('..')) return res.status(400).end();
    const u = new URL(req.url, 'http://x');
    ['action', 'path'].forEach(k => u.searchParams.delete(k));
    const target = E.BLUEMAP_ORIGIN.replace(/\/$/, '') + '/' + path + u.search;
    const r = await fetch(target, { signal: AbortSignal.timeout(10000) }).catch(() => null);
    if (!r) return res.status(502).send('Map server unreachable');
    res.setHeader('Content-Type', r.headers.get('content-type') || 'application/octet-stream');
    res.setHeader('Cache-Control', 'private, max-age=30');
    res.status(r.status).send(Buffer.from(await r.arrayBuffer()));
  },

  async apply(req, res) {
    if (req.method !== 'POST') return res.status(405).end();
    const s = readSession(req);
    if (!s || !s.inGuild) return res.status(401).end();
    const { ign, about } = req.body || {};
    if (!/^\.?[A-Za-z0-9_ ]{3,16}$/.test(ign || '') || !about || about.length > 600) return res.status(400).end();
    const r = await fetch(E.WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        allowed_mentions: { parse: [] },
        embeds: [{
          title: 'Whitelist application', color: 0x10b981,
          fields: [
            { name: 'Discord', value: `<@${s.id}> (${s.name})` },
            { name: 'Minecraft IGN', value: ign },
            { name: 'About', value: about },
          ],
        }],
      }),
    });
    res.status(r.ok ? 200 : 502).json({ ok: r.ok });
  },
};

module.exports = async (req, res) => {
  const name = req.query.action;
  if (!Object.hasOwn(routes, name)) return res.status(404).end();
  try { await routes[name](req, res); }
  catch (e) { console.error(e); res.status(500).json({ error: 'server' }); }
};
