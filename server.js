// Dardasha messenger server: REST + WebSocket + SQLite + WebRTC signaling
const express = require('express'), http = require('http'), path = require('path'), fs = require('fs');
const crypto = require('crypto'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const multer = require('multer'), { WebSocketServer } = require('ws'), Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(path.join(DATA, 'files'), { recursive: true });
let SECRET = process.env.JWT_SECRET;
if (!SECRET) { // generate once and persist, so logins survive restarts
  const f = path.join(DATA, '.secret');
  SECRET = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(f, SECRET, { mode: 0o600 });
}
const db = new Database(path.join(DATA, 'app.db'));
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pass TEXT NOT NULL, about TEXT DEFAULT '', last_seen INTEGER DEFAULT 0, hide_seen INTEGER DEFAULT 0, hide_read INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, type TEXT NOT NULL, name TEXT, owner INTEGER, dkey TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS members(chat_id INTEGER, user_id INTEGER, role TEXT DEFAULT 'member', PRIMARY KEY(chat_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, chat_id INTEGER, sender INTEGER, text TEXT, file TEXT, fname TEXT, reply_to INTEGER, ts INTEGER, deleted INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS m_chat ON messages(chat_id, id);
CREATE TABLE IF NOT EXISTS receipts(msg_id INTEGER, user_id INTEGER, status INTEGER, PRIMARY KEY(msg_id,user_id));
CREATE TABLE IF NOT EXISTS blocks(user_id INTEGER, blocked INTEGER, PRIMARY KEY(user_id,blocked));
`);
const q = (s) => db.prepare(s);

// --- tiny rate limiter (per IP) ---
const hits = new Map();
const limit = (max, ms) => (req, res, next) => {
  const k = req.ip + req.path, now = Date.now(), h = (hits.get(k) || []).filter(t => now - t < ms);
  h.push(now); hits.set(k, h);
  if (h.length > max) return res.status(429).json({ error: 'محاولات كثيرة، حاول لاحقًا' });
  next();
};
setInterval(() => hits.clear(), 3600e3);

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000', 'Permissions-Policy': 'camera=(self), microphone=(self)' });
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7) || req.query.t, SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'غير مصرّح' }); }
};
const token = (uid) => jwt.sign({ uid }, SECRET, { expiresIn: '30d' });
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, about: u.about });

app.post('/api/register', limit(10, 3600e3), (req, res) => {
  const { username, name, password } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'اسم المستخدم: 3-20 حرفًا إنجليزيًا أو أرقامًا أو _' });
  if (!name || name.length > 40) return res.status(400).json({ error: 'الاسم مطلوب' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'كلمة المرور 8 أحرف على الأقل' });
  try {
    const r = q('INSERT INTO users(username,name,pass) VALUES(?,?,?)').run(username.toLowerCase(), name, bcrypt.hashSync(password, 11));
    res.json({ token: token(r.lastInsertRowid) });
  } catch { res.status(409).json({ error: 'اسم المستخدم مستخدم' }); }
});
app.post('/api/login', limit(15, 900e3), (req, res) => {
  const { username, password } = req.body || {};
  const u = q('SELECT * FROM users WHERE username=?').get(String(username || '').toLowerCase());
  if (!u || !bcrypt.compareSync(String(password || ''), u.pass)) return res.status(401).json({ error: 'بيانات الدخول خاطئة' });
  res.json({ token: token(u.id) });
});
app.get('/api/me', auth, (req, res) => {
  const u = q('SELECT * FROM users WHERE id=?').get(req.uid);
  res.json({ ...pub(u), hide_seen: u.hide_seen, hide_read: u.hide_read, ice: iceServers() });
});
app.patch('/api/me', auth, (req, res) => {
  const { name, about, hide_seen, hide_read } = req.body || {};
  const u = q('SELECT * FROM users WHERE id=?').get(req.uid);
  q('UPDATE users SET name=?, about=?, hide_seen=?, hide_read=? WHERE id=?').run(
    (name || u.name).slice(0, 40), String(about ?? u.about).slice(0, 140), hide_seen ?? u.hide_seen ? 1 : 0, hide_read ?? u.hide_read ? 1 : 0, req.uid);
  res.json({ ok: true });
});
app.get('/api/users', auth, (req, res) => {
  const s = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (s.length < 3) return res.json([]); // exact-ish search only: no directory scraping
  res.json(q('SELECT id,username,name,about FROM users WHERE username=? AND id!=?').all(s, req.uid));
});
app.post('/api/block', auth, (req, res) => { q('INSERT OR IGNORE INTO blocks VALUES(?,?)').run(req.uid, +req.body.user); res.json({ ok: true }); });
app.post('/api/unblock', auth, (req, res) => { q('DELETE FROM blocks WHERE user_id=? AND blocked=?').run(req.uid, +req.body.user); res.json({ ok: true }); });

const isMember = (chat, uid) => !!q('SELECT 1 FROM members WHERE chat_id=? AND user_id=?').get(chat, uid);
const members = (chat) => q('SELECT user_id FROM members WHERE chat_id=?').all(chat).map(r => r.user_id);
const blocked = (a, b) => !!q('SELECT 1 FROM blocks WHERE (user_id=? AND blocked=?) OR (user_id=? AND blocked=?)').get(a, b, b, a);

app.post('/api/chats', auth, (req, res) => {
  const { type, username, name, usernames } = req.body || {};
  if (type === 'direct') {
    const o = q('SELECT id FROM users WHERE username=?').get(String(username || '').toLowerCase());
    if (!o || o.id === req.uid) return res.status(404).json({ error: 'المستخدم غير موجود' });
    const key = [req.uid, o.id].sort().join('-');
    let c = q('SELECT id FROM chats WHERE dkey=?').get(key);
    if (!c) {
      const r = q("INSERT INTO chats(type,dkey) VALUES('direct',?)").run(key);
      q('INSERT INTO members(chat_id,user_id) VALUES(?,?),(?,?)').run(r.lastInsertRowid, req.uid, r.lastInsertRowid, o.id);
      c = { id: r.lastInsertRowid };
    }
    return res.json({ id: c.id });
  }
  if (type === 'group') {
    const ids = [...new Set((usernames || []).slice(0, 255).map(n => q('SELECT id FROM users WHERE username=?').get(String(n).toLowerCase())).filter(Boolean).map(u => u.id))];
    if (!name || !ids.length) return res.status(400).json({ error: 'اسم المجموعة وعضو واحد على الأقل' });
    const r = q("INSERT INTO chats(type,name,owner) VALUES('group',?,?)").run(String(name).slice(0, 50), req.uid);
    q("INSERT INTO members(chat_id,user_id,role) VALUES(?,?, 'admin')").run(r.lastInsertRowid, req.uid);
    ids.filter(i => i !== req.uid).forEach(i => q('INSERT INTO members(chat_id,user_id) VALUES(?,?)').run(r.lastInsertRowid, i));
    members(r.lastInsertRowid).forEach(u => push(u, { t: 'chat', chat: r.lastInsertRowid }));
    return res.json({ id: r.lastInsertRowid });
  }
  res.status(400).json({ error: 'نوع غير صالح' });
});
app.get('/api/chats', auth, (req, res) => {
  const rows = q('SELECT c.* FROM chats c JOIN members m ON m.chat_id=c.id WHERE m.user_id=?').all(req.uid);
  res.json(rows.map(c => {
    const mem = q('SELECT u.id,u.username,u.name,u.about FROM members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=?').all(c.id);
    const last = q('SELECT id,sender,text,file,ts,deleted FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 1').get(c.id);
    const unread = q(`SELECT COUNT(*) n FROM messages m WHERE chat_id=? AND sender!=? AND deleted=0 AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.msg_id=m.id AND r.user_id=? AND r.status=2)`).get(c.id, req.uid, req.uid).n;
    const other = c.type === 'direct' ? mem.find(m => m.id !== req.uid) : null;
    return { id: c.id, type: c.type, title: other ? other.name : c.name, members: mem, other, last, unread };
  }).sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0)));
});
const shape = (m, me) => {
  const st = q('SELECT MIN(status) s FROM receipts WHERE msg_id=?').get(m.id).s || 0;
  const cnt = q('SELECT COUNT(*) n FROM receipts WHERE msg_id=?').get(m.id).n;
  const need = members(m.chat_id).length - 1;
  return { id: m.id, chat: m.chat_id, sender: m.sender, text: m.deleted ? null : m.text, file: m.deleted ? null : m.file, fname: m.fname, reply: m.reply_to, ts: m.ts, deleted: !!m.deleted,
    status: m.sender === me ? (cnt >= need ? st : 0) : undefined };
};
app.get('/api/chats/:id/messages', auth, (req, res) => {
  if (!isMember(+req.params.id, req.uid)) return res.status(403).json({ error: 'ممنوع' });
  const before = +req.query.before || 9e15;
  const rows = q('SELECT * FROM messages WHERE chat_id=? AND id<? ORDER BY id DESC LIMIT 50').all(+req.params.id, before).reverse();
  res.json(rows.map(m => shape(m, req.uid)));
});
const up = multer({ dest: path.join(DATA, 'files'), limits: { fileSize: 25 * 1024 * 1024 } });
app.post('/api/upload', auth, limit(60, 3600e3), up.single('f'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لا ملف' });
  res.json({ file: req.file.filename, fname: String(req.file.originalname).slice(0, 100) });
});
app.get('/api/files/:name', auth, (req, res) => {
  const name = path.basename(req.params.name);
  const m = q('SELECT chat_id FROM messages WHERE file=? AND deleted=0').get(name);
  if (!m || !isMember(m.chat_id, req.uid)) return res.status(403).end();
  res.set('Content-Disposition', 'inline'); res.set('Content-Security-Policy', "default-src 'none'; sandbox");
  res.sendFile(path.join(DATA, 'files', name));
});
function iceServers() { // add your own TURN in env for calls behind strict NATs
  const s = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URL) s.push({ urls: process.env.TURN_URL, username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  return s;
}

// --- realtime ---
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 256 * 1024 });
const online = new Map(); // uid -> Set<ws>
function push(uid, obj) { (online.get(uid) || []).forEach(w => w.readyState === 1 && w.send(JSON.stringify(obj))); }
function presence(uid, on) {
  const u = q('SELECT hide_seen FROM users WHERE id=?').get(uid);
  if (u.hide_seen) return;
  const peers = q('SELECT DISTINCT user_id FROM members WHERE chat_id IN (SELECT chat_id FROM members WHERE user_id=?) AND user_id!=?').all(uid, uid);
  peers.forEach(p => push(p.user_id, { t: 'presence', user: uid, on, ts: Date.now() }));
}
wss.on('connection', (ws, req) => {
  let uid;
  try { uid = jwt.verify(new URL(req.url, 'http://x').searchParams.get('t'), SECRET).uid; } catch { return ws.close(4001); }
  if (!online.has(uid)) online.set(uid, new Set());
  online.get(uid).add(ws); ws.alive = true; ws.on('pong', () => ws.alive = true);
  if (online.get(uid).size === 1) presence(uid, true);
  // mark pending as delivered
  q('SELECT m.id,m.chat_id,m.sender FROM messages m JOIN members mb ON mb.chat_id=m.chat_id AND mb.user_id=? WHERE m.sender!=? AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.msg_id=m.id AND r.user_id=?)').all(uid, uid, uid)
    .forEach(m => { q('INSERT OR IGNORE INTO receipts VALUES(?,?,1)').run(m.id, uid); push(m.sender, { t: 'receipt', id: m.id, chat: m.chat_id, user: uid, status: 1 }); });

  ws.on('message', (raw) => {
    let d; try { d = JSON.parse(raw); } catch { return; }
    const chat = +d.chat;
    if (d.t === 'send') {
      if (!isMember(chat, uid)) return;
      const text = String(d.text || '').slice(0, 4000);
      if (!text && !d.file) return;
      const mem = members(chat);
      if (mem.length === 2 && blocked(mem[0], mem[1])) return ws.send(JSON.stringify({ t: 'error', error: 'لا يمكن الإرسال' }));
      const r = q('INSERT INTO messages(chat_id,sender,text,file,fname,reply_to,ts) VALUES(?,?,?,?,?,?,?)')
        .run(chat, uid, text, d.file ? path.basename(String(d.file)) : null, d.fname ? String(d.fname).slice(0, 100) : null, d.reply ? +d.reply : null, Date.now());
      const m = q('SELECT * FROM messages WHERE id=?').get(r.lastInsertRowid);
      mem.forEach(u => {
        if (u !== uid && online.has(u)) { q('INSERT OR IGNORE INTO receipts VALUES(?,?,1)').run(m.id, u); }
        push(u, { t: 'msg', m: shape(m, u), cid: u === uid ? d.cid : undefined });
      });
      const s = shape(m, uid); push(uid, { t: 'receipt', id: m.id, chat, status: s.status });
    } else if (d.t === 'read') {
      if (!isMember(chat, uid)) return;
      const hide = q('SELECT hide_read FROM users WHERE id=?').get(uid).hide_read;
      q('SELECT id,sender FROM messages WHERE chat_id=? AND sender!=? AND id<=?').all(chat, uid, +d.upto).forEach(m => {
        q('INSERT INTO receipts VALUES(?,?,?) ON CONFLICT(msg_id,user_id) DO UPDATE SET status=MAX(status,excluded.status)').run(m.id, uid, 2);
        if (!hide) push(m.sender, { t: 'receipt', id: m.id, chat, user: uid, status: 2 });
      });
    } else if (d.t === 'typing') {
      if (isMember(chat, uid)) members(chat).filter(u => u !== uid).forEach(u => push(u, { t: 'typing', chat, user: uid }));
    } else if (d.t === 'delete') { // delete for everyone (own messages only)
      const m = q('SELECT * FROM messages WHERE id=? AND sender=?').get(+d.id, uid);
      if (!m) return;
      q("UPDATE messages SET deleted=1, text=NULL, file=NULL WHERE id=?").run(m.id);
      members(m.chat_id).forEach(u => push(u, { t: 'deleted', id: m.id, chat: m.chat_id }));
    } else if (['call-offer', 'call-answer', 'call-ice', 'call-end', 'call-reject'].includes(d.t)) {
      const to = +d.to;
      if (blocked(uid, to) || !q('SELECT 1 FROM members a JOIN members b ON a.chat_id=b.chat_id WHERE a.user_id=? AND b.user_id=?').get(uid, to)) return;
      push(to, { t: d.t, from: uid, sdp: d.sdp, ice: d.ice, video: d.video });
    }
  });
  ws.on('close', () => {
    const s = online.get(uid); s.delete(ws);
    if (!s.size) { online.delete(uid); q('UPDATE users SET last_seen=? WHERE id=?').run(Date.now(), uid); presence(uid, false); }
  });
});
setInterval(() => wss.clients.forEach(w => { if (!w.alive) return w.terminate(); w.alive = false; w.ping(); }), 30000);
server.listen(PORT, () => console.log('Dardasha running on :' + PORT));
