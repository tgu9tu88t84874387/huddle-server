'use strict';

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

/* ═══════════════ КОНФИГ ═══════════════ */
const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || 'huddle-secret-change-me';
const DB_FILE = path.join(__dirname, 'huddle-db.json');

/* ═══════════════ БД (JSON-файл) ═══════════════ */
let DB = { users: {}, messages: {}, stories: [], posts: [], communities: [] };

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) DB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) { console.warn('DB load error:', e.message); }
}
let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); }
    catch (e) { console.error('DB save error:', e.message); }
  }, 300);
}
loadDB();

/* ═══════════════ EXPRESS ═══════════════ */
const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));
// Health check для Railway / Koyeb
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

function signToken(user) {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function authMW(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}

app.get('/health', (req, res) => res.json({
  ok: true,
  users: Object.keys(DB.users).length,
  online: onlineUsers.size
}));

app.post('/api/register', async (req, res) => {
  const { username, email, password, phone } = req.body || {};
  if (!username || !password || password.length < 6)
    return res.status(400).json({ error: 'username, password (min 6) required' });
  const key = username.toLowerCase();
  if (DB.users[key]) return res.status(409).json({ error: 'Username taken' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { username, email: email || '', phone: phone || '', passwordHash, avatar: null, createdAt: new Date().toISOString() };
  DB.users[key] = user;
  saveDB();
  res.json({ user: { username, email: user.email, phone: user.phone }, token: signToken(user) });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  const u = DB.users[username.toLowerCase()];
  if (!u) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ user: { username: u.username, email: u.email, phone: u.phone }, token: signToken(u) });
});

app.get('/api/me', authMW, (req, res) => {
  const u = DB.users[req.user.username.toLowerCase()];
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ user: { username: u.username, email: u.email, phone: u.phone, avatar: u.avatar, createdAt: u.createdAt } });
});

app.patch('/api/me', authMW, (req, res) => {
  const u = DB.users[req.user.username.toLowerCase()];
  if (!u) return res.status(404).json({ error: 'Not found' });
  const { email, phone, avatar } = req.body || {};
  if (email !== undefined) u.email = email;
  if (phone !== undefined) u.phone = phone;
  if (avatar !== undefined) u.avatar = avatar;
  saveDB();
  res.json({ user: { username: u.username, email: u.email, phone: u.phone, avatar: u.avatar } });
});

app.get('/api/search', authMW, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const out = [];
  Object.values(DB.users).forEach((u) => {
    const un = u.username.toLowerCase();
    const em = String(u.email || '').toLowerCase();
    const ph = String(u.phone || '').toLowerCase();
    if (!q || un.includes(q) || em.includes(q) || ph.includes(q)) {
      out.push({ username: u.username, email: u.email || '', phone: u.phone || '', avatar: u.avatar || null, online: onlineUsers.has(u.username) });
    }
  });
  res.json({ users: out.slice(0, 50) });
});

/* ═══════════════ HTTP + WEBSOCKET ═══════════════ */
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
const onlineUsers = new Map();

function log(...args) { console.log('[Signal]', new Date().toISOString(), ...args); }
function sendTo(ws, msg) { if (ws && ws.readyState === WebSocket.OPEN) { try { ws.send(JSON.stringify(msg)); } catch (e) {} } }
function sendToUser(username, msg) { const ws = onlineUsers.get(username); if (ws) sendTo(ws, msg); }
function broadcast(msg, except) {
  const raw = JSON.stringify(msg);
  onlineUsers.forEach((ws, uname) => {
    if (uname === except) return;
    if (ws.readyState === WebSocket.OPEN) { try { ws.send(raw); } catch (e) {} }
  });
}
function searchUsers(q) {
  q = String(q || '').toLowerCase().trim();
  const out = [];
  Object.values(DB.users).forEach((u) => {
    const un = u.username.toLowerCase();
    const em = String(u.email || '').toLowerCase();
    const ph = String(u.phone || '').toLowerCase();
    if (!q || un.includes(q) || em.includes(q) || ph.includes(q)) {
      out.push({ username: u.username, email: u.email || '', phone: u.phone || '', avatar: u.avatar || null, online: onlineUsers.has(u.username) });
    }
  });
  return out.slice(0, 50);
}

wss.on('connection', (ws) => {
  let me = null;
  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch (e) { return; }
    if (!m || !m.type) return;

    if (m.type === 'register') {
  const uname = String(m.username || '').trim();
  if (!uname) return;
  me = uname;
  onlineUsers.set(uname, ws);
  const key = uname.toLowerCase();
  if (!DB.users[key]) {
    DB.users[key] = { username: uname, email: m.email || '', phone: m.phone || '', passwordHash: '', avatar: m.avatar || null, createdAt: new Date().toISOString() };
    log('auto-create user:', uname);
  } else {
    if (m.email !== undefined) DB.users[key].email = m.email;
    if (m.phone !== undefined) DB.users[key].phone = m.phone;
    if (m.avatar !== undefined) DB.users[key].avatar = m.avatar;
  }
  saveDB();
  log('register', uname, '| online:', onlineUsers.size, '| total users:', Object.keys(DB.users).length);
  sendTo(ws, { type: 'registered', username: uname });
  broadcast({ type: 'user-online', username: uname }, uname);
  return;
}

    if (m.type === 'profile-update') {
      if (!me) return;
      const u = DB.users[me.toLowerCase()];
      if (!u) return;
      if (m.email !== undefined) u.email = m.email;
      if (m.phone !== undefined) u.phone = m.phone;
      if (m.avatar !== undefined) u.avatar = m.avatar;
      saveDB();
      return;
    }

    if (m.type === 'user-search') { sendTo(ws, { type: 'user-results', query: m.query, users: searchUsers(m.query) }); return; }
    if (m.type === 'user-list') { sendTo(ws, { type: 'user-results', query: '', users: searchUsers('') }); return; }
    if (m.type === 'ping') { sendTo(ws, { type: 'pong', t: m.t }); return; }
    if (m.type === 'pong') return;

    if (m.type === 'chat-message') {
      if (!m.from && me) m.from = me;
      if (!m.to) return;
      const chatId = [m.from, m.to].sort().join('__');
      if (!DB.messages[chatId]) DB.messages[chatId] = [];
      DB.messages[chatId].push({
        id: m.id || ('m_' + Date.now()),
        from: m.from, to: m.to,
        content: m.content || '',
        type: m.media_type || m.type || 'text',
        media_key: m.media_key || null,
        duration: m.duration || 0,
        createdAt: m.created_at || new Date().toISOString()
      });
      saveDB();
      sendToUser(m.to, m);
      if (m.groupId) {
        const g = DB.communities.find((c) => String(c.id) === String(m.groupId));
        if (g) (g.members || []).forEach((mem) => { if (mem !== m.from) sendToUser(mem, m); });
      }
      return;
    }

    if (m.type === 'history-request') {
      const chatId = [m.with, me].sort().join('__');
      sendTo(ws, { type: 'history', with: m.with, messages: DB.messages[chatId] || [] });
      return;
    }

    if (m.type === 'story-broadcast') { if (m.story) { DB.stories.push(m.story); saveDB(); } broadcast(m, me); return; }
    if (m.type === 'post-broadcast') { if (m.post) { DB.posts.push(m.post); saveDB(); } broadcast(m, me); return; }
    if (m.type === 'comment-broadcast') { broadcast(m, me); return; }

    if (['call-invite','offer','answer','candidate','hangup','call-invite-group'].includes(m.type)) {
      if (m.to) sendToUser(m.to, m);
      return;
    }
    broadcast(m, me);
  });

  ws.on('close', () => {
    if (me) {
      onlineUsers.delete(me);
      log('disconnect', me, '| online:', onlineUsers.size);
      broadcast({ type: 'user-offline', username: me }, me);
    }
  });
  ws.on('error', (e) => log('ws error', e.message));
});

process.on('SIGINT', () => {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); } catch (e) {}
  process.exit(0);
});

server.listen(PORT, () => {
  log('Huddle Server (API + Signal) запущен');
  log('HTTP  : http://localhost:' + PORT);
  log('WS    : ws://localhost:' + PORT + '/ws');
  log('Users : ' + Object.keys(DB.users).length);
});