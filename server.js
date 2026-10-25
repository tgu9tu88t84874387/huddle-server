'use strict';
/* ═══════════════════════════════════════════════════════════════════
   Huddle Server (API + Signal)
   Один процесс обслуживает:
     - HTTP API   : /api/register, /api/login, /api/me, /api/search, ...
     - Channel posts: /api/channels/:id/posts, /api/posts, /api/communities/:id/posts
     - WebSocket  : /ws  (чат, звонки, истории, посты, presence)
   Запуск: node server.js
   Порт : process.env.PORT || 8787
   ═══════════════════════════════════════════════════════════════════ */
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
/* ─────────── КОНФИГ ─────────── */
const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || 'huddle-secret-change-me';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'huddle-db.json');
/* ─────────── БАЗА (JSON-файл) ─────────── */
let DB = { users: {}, messages: {}, stories: [], posts: [], communities: [], channelPosts: {} };
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      DB.users = parsed.users || {};
      DB.messages = parsed.messages || {};
      DB.stories = parsed.stories || [];
      DB.posts = parsed.posts || [];
      DB.communities = parsed.communities || [];
      DB.channelPosts = parsed.channelPosts || {};
      console.log('[DB] loaded:', DB_FILE, '| users:', Object.keys(DB.users).length);
    } else {
      console.log('[DB] new file will be created at', DB_FILE);
    }
  } catch (e) {
    console.warn('[DB] load error:', e.message);
  }
}
let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2));
    } catch (e) {
      console.error('[DB] save error:', e.message);
    }
  }, 300);
}
function saveDBSync() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); }
  catch (e) { console.error('[DB] sync save error:', e.message); }
}
loadDB();
/* ─────────── EXPRESS ─────────── */
const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Authorization'],
}));
app.options('*', cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
/* ─────────── AUTH ─────────── */
function signToken(user) {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function authMW(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}
/** Auth optional: if token present and valid → req.user, else continue */
function authOptional(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return next();
  try { req.user = jwt.verify(token, JWT_SECRET); } catch (_) {}
  next();
}
/* ─────────── HEALTH ─────────── */
app.get('/', (req, res) => {
  res.json({
    ok: true,
    name: 'huddle-server',
    version: '1.1.0',
    users: Object.keys(DB.users).length,
    online: onlineUsers.size,
    channelPosts: Object.keys(DB.channelPosts || {}).length,
    time: new Date().toISOString(),
  });
});
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    users: Object.keys(DB.users).length,
    online: onlineUsers.size,
    uptime: process.uptime(),
    time: new Date().toISOString(),
  });
});
/* ─────────── REGISTER ─────────── */
app.post('/api/register', async (req, res) => {
  const { username, email, password, phone } = req.body || {};
  if (!username || !password || String(password).length < 6) {
    return res.status(400).json({ error: 'username and password (min 6) required' });
  }
  const key = String(username).toLowerCase();
  if (DB.users[key]) return res.status(409).json({ error: 'Username taken' });
  try {
    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = {
      username: String(username),
      email: email || '',
      phone: phone || '',
      passwordHash,
      avatar: null,
      createdAt: new Date().toISOString(),
    };
    DB.users[key] = user;
    saveDB();
    res.json({
      user: { username: user.username, email: user.email, phone: user.phone, avatar: user.avatar },
      token: signToken(user),
    });
  } catch (e) {
    console.error('[register]', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});
/* ─────────── LOGIN ─────────── */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }
  const u = DB.users[String(username).toLowerCase()];
  if (!u) return res.status(401).json({ error: 'Invalid credentials' });
  try {
    const ok = await bcrypt.compare(String(password), u.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({
      user: { username: u.username, email: u.email, phone: u.phone, avatar: u.avatar },
      token: signToken(u),
    });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: 'Server error' });
  }
});
/* ─────────── ME ─────────── */
app.get('/api/me', authMW, (req, res) => {
  const u = DB.users[req.user.username.toLowerCase()];
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({
    user: {
      username: u.username,
      email: u.email,
      phone: u.phone,
      avatar: u.avatar,
      createdAt: u.createdAt,
    },
  });
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
/* ─────────── SEARCH (HTTP) ─────────── */
app.get('/api/search', authMW, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const type = String(req.query.type || 'users').toLowerCase();
  if (type !== 'users') return res.json({ results: [] });
  const out = [];
  Object.values(DB.users).forEach((u) => {
    const un = String(u.username || '').toLowerCase();
    const em = String(u.email || '').toLowerCase();
    const ph = String(u.phone || '').toLowerCase();
    if (!q || un.includes(q) || em.includes(q) || ph.includes(q)) {
      out.push({
        username: u.username,
        name: u.username,
        email: u.email || '',
        phone: u.phone || '',
        avatar: u.avatar || null,
        online: onlineUsers.has(u.username),
      });
    }
  });
  res.json({ results: out.slice(0, 50) });
});
/* ─────────── ALL USERS ─────────── */
app.get('/api/users', authMW, (req, res) => {
  const users = Object.values(DB.users).map((u) => ({
    username: u.username,
    name: u.username,
    email: u.email || '',
    phone: u.phone || '',
    avatar: u.avatar || null,
    online: onlineUsers.has(u.username),
  }));
  res.json({ results: users.slice(0, 200) });
});
/* ─────────── GET USER BY NAME ─────────── */
app.get('/api/users/:name', authMW, (req, res) => {
  const name = String(req.params.name || '').toLowerCase();
  const u = DB.users[name];
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({
    user: {
      username: u.username,
      email: u.email || '',
      phone: u.phone || '',
      avatar: u.avatar || null,
      online: onlineUsers.has(u.username),
    },
  });
});

/* ═══════════════════════════════════════════════════════════════════
   CHANNEL / PUBLIC POSTS (HTTP) — видно всем, хранится в DB.channelPosts
   ═══════════════════════════════════════════════════════════════════ */
function uid(prefix) {
  return (prefix || 'post') + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
}
function listChannelPosts(channelId) {
  const id = String(channelId);
  if (!DB.channelPosts[id]) DB.channelPosts[id] = [];
  return DB.channelPosts[id];
}
function normalizeChannelPost(body, channelId, author) {
  const text = String((body && (body.text || body.content)) || '').slice(0, 20000);
  const attachments = Array.isArray(body && body.attachments) ? body.attachments : [];
  return {
    id: (body && (body.id || body.post_id)) || uid('post'),
    author: author || (body && body.author) || 'anon',
    text,
    content: text,
    title: String((body && body.title) || '').slice(0, 200),
    attachments,
    reactions: Array.isArray(body && body.reactions) ? body.reactions : [],
    comments: Array.isArray(body && body.comments) ? body.comments : [],
    commentCount: 0,
    views: 0,
    pinned: false,
    edited: false,
    channel_id: String(channelId),
    created_at: (body && body.created_at) || new Date().toISOString(),
    server: true,
  };
}
function findPostAnywhere(postId) {
  const pid = String(postId);
  for (const cid of Object.keys(DB.channelPosts || {})) {
    const p = (DB.channelPosts[cid] || []).find((x) => String(x.id) === pid);
    if (p) return { channelId: cid, post: p };
  }
  return null;
}

// GET list
function handleListChannelPosts(req, res) {
  const channelId = req.params.id || req.query.channel_id;
  if (!channelId) return res.status(400).json({ error: 'channel_id required' });
  res.json({ ok: true, posts: listChannelPosts(channelId).slice() });
}
app.get('/api/channels/:id/posts', authOptional, handleListChannelPosts);
app.get('/api/communities/:id/posts', authOptional, handleListChannelPosts);
app.get('/api/posts', authOptional, (req, res) => {
  if (req.query.channel_id) {
    return res.json({ ok: true, posts: listChannelPosts(req.query.channel_id).slice() });
  }
  // global feed: all channel posts + legacy DB.posts
  const out = [];
  Object.keys(DB.channelPosts || {}).forEach((cid) => {
    (DB.channelPosts[cid] || []).forEach((p) => out.push(Object.assign({}, p, { channel_id: cid })));
  });
  (DB.posts || []).forEach((p) => out.push(p));
  out.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  res.json({ ok: true, posts: out.slice(0, 150) });
});

// POST create
function handleCreateChannelPost(req, res) {
  const channelId = req.params.id || (req.body && (req.body.channel_id || req.body.channelId));
  if (!channelId) return res.status(400).json({ error: 'channel_id required' });
  const author = (req.user && req.user.username) || (req.body && req.body.author) || 'anon';
  const post = normalizeChannelPost(req.body || {}, channelId, author);
  const list = listChannelPosts(channelId);
  list.unshift(post);
  if (list.length > 500) list.length = 500;
  // also mirror into global posts feed (for /api/posts without channel filter)
  DB.posts.unshift({
    id: post.id,
    author: post.author,
    title: post.title || ('📢 канал'),
    content: post.text,
    created_at: post.created_at,
    likes: 0,
    views: 0,
    channel_id: String(channelId),
    source: 'channel',
    attachment: (post.attachments && post.attachments[0]) || null,
  });
  if (DB.posts.length > 1000) DB.posts = DB.posts.slice(0, 1000);
  saveDB();
  // live push to online clients
  try {
    broadcast({
      type: 'channel-post-broadcast',
      broadcast: true,
      from: post.author,
      channel_id: String(channelId),
      post,
    }, null);
    broadcast({
      type: 'post-broadcast',
      broadcast: true,
      from: post.author,
      post: {
        id: post.id,
        author: post.author,
        title: post.title || '📢 канал',
        content: post.text,
        created_at: post.created_at,
        channel_id: String(channelId),
        source: 'channel',
        likes: 0,
        views: 0,
      },
    }, null);
  } catch (_) {}
  res.status(201).json({ ok: true, post, id: post.id });
}
app.post('/api/channels/:id/posts', authOptional, handleCreateChannelPost);
app.post('/api/communities/:id/posts', authOptional, handleCreateChannelPost);
app.post('/api/posts', authOptional, handleCreateChannelPost);

// DELETE
app.delete('/api/channels/:id/posts/:postId', authOptional, (req, res) => {
  const list = listChannelPosts(req.params.id);
  const before = list.length;
  DB.channelPosts[String(req.params.id)] = list.filter((p) => String(p.id) !== String(req.params.postId));
  DB.posts = (DB.posts || []).filter((p) => String(p.id) !== String(req.params.postId));
  saveDB();
  res.json({ ok: DB.channelPosts[String(req.params.id)].length < before });
});

// Reactions
app.post('/api/channels/:id/posts/:postId/reactions', authOptional, (req, res) => {
  const list = listChannelPosts(req.params.id);
  const post = list.find((p) => String(p.id) === String(req.params.postId));
  if (!post) return res.status(404).json({ error: 'post not found' });
  const emoji = String((req.body && req.body.emoji) || '❤️').slice(0, 8);
  const username = (req.user && req.user.username) || (req.body && req.body.author) || 'anon';
  post.reactions = Array.isArray(post.reactions) ? post.reactions : [];
  let r = post.reactions.find((x) => x.emoji === emoji);
  if (!r) { r = { emoji, users: [] }; post.reactions.push(r); }
  const i = r.users.indexOf(username);
  if (i >= 0) r.users.splice(i, 1); else r.users.push(username);
  post.reactions = post.reactions.filter((x) => (x.users || []).length);
  saveDB();
  res.json({ ok: true, reactions: post.reactions });
});
app.post('/api/posts/:postId/reactions', authOptional, (req, res) => {
  const found = findPostAnywhere(req.params.postId);
  if (!found) return res.status(404).json({ error: 'post not found' });
  req.params.id = found.channelId;
  // reuse
  const post = found.post;
  const emoji = String((req.body && req.body.emoji) || '❤️').slice(0, 8);
  const username = (req.user && req.user.username) || (req.body && req.body.author) || 'anon';
  post.reactions = Array.isArray(post.reactions) ? post.reactions : [];
  let r = post.reactions.find((x) => x.emoji === emoji);
  if (!r) { r = { emoji, users: [] }; post.reactions.push(r); }
  const i = r.users.indexOf(username);
  if (i >= 0) r.users.splice(i, 1); else r.users.push(username);
  post.reactions = post.reactions.filter((x) => (x.users || []).length);
  saveDB();
  res.json({ ok: true, reactions: post.reactions });
});

// Comments
app.get('/api/channels/:id/posts/:postId/comments', authOptional, (req, res) => {
  const list = listChannelPosts(req.params.id);
  const post = list.find((p) => String(p.id) === String(req.params.postId));
  if (!post) return res.status(404).json({ error: 'post not found' });
  res.json({ ok: true, comments: post.comments || [] });
});
app.post('/api/channels/:id/posts/:postId/comments', authOptional, (req, res) => {
  const list = listChannelPosts(req.params.id);
  const post = list.find((p) => String(p.id) === String(req.params.postId));
  if (!post) return res.status(404).json({ error: 'post not found' });
  const text = String((req.body && req.body.text) || '').trim().slice(0, 5000);
  if (!text) return res.status(400).json({ error: 'text required' });
  const comment = {
    id: uid('cmt'),
    author: (req.user && req.user.username) || 'anon',
    text,
    created_at: new Date().toISOString(),
  };
  post.comments = post.comments || [];
  post.comments.push(comment);
  post.commentCount = post.comments.length;
  saveDB();
  res.status(201).json({ ok: true, comment });
});
app.get('/api/posts/:postId/comments', authOptional, (req, res) => {
  const channelId = req.query.channel_id;
  if (channelId) {
    const list = listChannelPosts(channelId);
    const post = list.find((p) => String(p.id) === String(req.params.postId));
    if (!post) return res.status(404).json({ error: 'post not found' });
    return res.json({ ok: true, comments: post.comments || [] });
  }
  const found = findPostAnywhere(req.params.postId);
  if (!found) return res.status(404).json({ error: 'post not found' });
  res.json({ ok: true, comments: found.post.comments || [] });
});
app.post('/api/posts/:postId/comments', authOptional, (req, res) => {
  const channelId = (req.body && req.body.channel_id) || req.query.channel_id;
  let post = null;
  if (channelId) {
    post = listChannelPosts(channelId).find((p) => String(p.id) === String(req.params.postId));
  } else {
    const found = findPostAnywhere(req.params.postId);
    if (found) post = found.post;
  }
  if (!post) return res.status(404).json({ error: 'post not found' });
  const text = String((req.body && req.body.text) || '').trim().slice(0, 5000);
  if (!text) return res.status(400).json({ error: 'text required' });
  const comment = {
    id: uid('cmt'),
    author: (req.user && req.user.username) || 'anon',
    text,
    created_at: new Date().toISOString(),
  };
  post.comments = post.comments || [];
  post.comments.push(comment);
  post.commentCount = post.comments.length;
  saveDB();
  res.status(201).json({ ok: true, comment });
});

/* ═══════════════ HTTP + WEBSOCKET ═══════════════ */
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });
/* Кто онлайн: username -> ws */
const onlineUsers = new Map();
/* ─── Хелперы ─── */
function log(...args) {
  console.log('[Signal]', new Date().toISOString(), ...args);
}
function sendTo(ws, msg) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(msg)); } catch (e) {}
  }
}
function sendToUser(username, msg) {
  const ws = onlineUsers.get(username);
  if (ws) sendTo(ws, msg);
}
function broadcast(msg, except) {
  const raw = JSON.stringify(msg);
  onlineUsers.forEach((ws, uname) => {
    if (uname === except) return;
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(raw); } catch (e) {}
    }
  });
}
function searchUsers(q) {
  q = String(q || '').toLowerCase().trim();
  const out = [];
  Object.values(DB.users).forEach((u) => {
    const un = String(u.username || '').toLowerCase();
    const em = String(u.email || '').toLowerCase();
    const ph = String(u.phone || '').toLowerCase();
    if (!q || un.includes(q) || em.includes(q) || ph.includes(q)) {
      out.push({
        username: u.username,
        name: u.username,
        email: u.email || '',
        phone: u.phone || '',
        avatar: u.avatar || null,
        online: onlineUsers.has(u.username),
      });
    }
  });
  return out.slice(0, 50);
}
/* ─── WS: соединение ─── */
wss.on('connection', (ws) => {
  let me = null;
  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch (e) { return; }
    if (!m || !m.type) return;
    /* ─── Регистрация ─── */
    if (m.type === 'register') {
      const uname = String(m.username || '').trim();
      if (!uname) return;
      me = uname;
      onlineUsers.set(uname, ws);
      const u = DB.users[uname.toLowerCase()];
      if (u) {
        if (m.email !== undefined) u.email = m.email;
        if (m.phone !== undefined) u.phone = m.phone;
        if (m.avatar !== undefined) u.avatar = m.avatar;
        saveDB();
      }
      log('register', uname, '| online:', onlineUsers.size);
      sendTo(ws, { type: 'registered', username: uname });
      broadcast({ type: 'user-online', username: uname }, uname);
      return;
    }
    /* ─── Presence ─── */
    if (m.type === 'presence') {
      if (m.from && !onlineUsers.has(m.from)) onlineUsers.set(m.from, ws);
      return;
    }
    /* ─── Профиль ─── */
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
    /* ─── Поиск через WS ─── */
    if (m.type === 'user-search') {
      sendTo(ws, { type: 'user-results', query: m.query, users: searchUsers(m.query) });
      return;
    }
    if (m.type === 'user-list') {
      sendTo(ws, { type: 'user-results', query: '', users: searchUsers('') });
      return;
    }
    /* ─── Пинг/понг ─── */
    if (m.type === 'ping') { sendTo(ws, { type: 'pong', t: m.t }); return; }
    if (m.type === 'pong') return;
    /* ─── Сообщения ─── */
    if (m.type === 'chat-message') {
      if (!m.from && me) m.from = me;
      if (!m.to) return;
      const chatId = [m.from, m.to].sort().join('__');
      if (!DB.messages[chatId]) DB.messages[chatId] = [];
      DB.messages[chatId].push({
        id: m.id || ('m_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7)),
        from: m.from,
        to: m.to,
        content: m.content || '',
        type: m.media_type || m.type || 'text',
        media_key: m.media_key || null,
        duration: m.duration || 0,
        createdAt: m.created_at || new Date().toISOString(),
      });
      saveDB();
      sendToUser(m.to, m);
      if (m.groupId) {
        const g = DB.communities.find((c) => String(c.id) === String(m.groupId));
        if (g) (g.members || []).forEach((mem) => {
          if (mem !== m.from) sendToUser(mem, m);
        });
      }
      return;
    }
    if (m.type === 'history-request') {
      const chatId = [m.with, me].sort().join('__');
      sendTo(ws, { type: 'history', with: m.with, messages: DB.messages[chatId] || [] });
      return;
    }
    /* ─── Истории / посты / комментарии / посты каналов ─── */
    if (m.type === 'story-broadcast') {
      if (m.story) { DB.stories.push(m.story); saveDB(); }
      broadcast(m, me);
      return;
    }
    if (m.type === 'post-broadcast') {
      if (m.post) { DB.posts.push(m.post); saveDB(); }
      broadcast(m, me);
      return;
    }
    if (m.type === 'channel-post-broadcast') {
      if (m.post && m.channel_id) {
        const list = listChannelPosts(m.channel_id);
        if (!list.some((p) => String(p.id) === String(m.post.id))) {
          list.unshift(Object.assign({}, m.post, { channel_id: String(m.channel_id), server: true }));
          if (list.length > 500) list.length = 500;
          saveDB();
        }
      }
      broadcast(m, me);
      return;
    }
    if (m.type === 'comment-broadcast') {
      broadcast(m, me);
      return;
    }
    /* ─── Звонки ─── */
    if (['call-invite', 'offer', 'answer', 'candidate', 'hangup', 'call-invite-group'].includes(m.type)) {
      if (m.to) sendToUser(m.to, m);
      return;
    }
    /* ─── Прочее: рассылаем всем, кроме отправителя ─── */
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
/* ─── Graceful shutdown ─── */
function shutdown(reason) {
  log('shutdown:', reason);
  try { saveDBSync(); } catch (e) {}
  wss.clients.forEach((c) => { try { c.close(); } catch (e) {} });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (e) => { log('uncaught:', e.message); });
process.on('unhandledRejection', (e) => { log('unhandled:', e && e.message); });
/* ─── Старт ─── */
server.listen(PORT, '0.0.0.0', () => {
  log('Huddle Server (API + Signal) запущен');
  log('HTTP  : http://localhost:' + PORT);
  log('WS    : ws://localhost:' + PORT + '/ws');
  log('Users : ' + Object.keys(DB.users).length);
  log('Channel posts API: /api/channels/:id/posts , /api/posts');
  log('');
  log('На хостинге используй:');
  log('  health: https://<домен>/health');
  log('  posts : https://<домен>/api/posts');
  log('  ws    : wss://<домен>/ws');
});
