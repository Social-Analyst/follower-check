const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { IgApiClient } = require('instagram-private-api');
const { createClient } = require('@supabase/supabase-js');

const { SUPABASE_URL, SUPABASE_SERVICE_KEY, SESSION_SECRET } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !SESSION_SECRET) {
  console.error('Missing env vars: SUPABASE_URL, SUPABASE_SERVICE_KEY, SESSION_SECRET');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
const KEY = crypto.createHash('sha256').update(SESSION_SECRET).digest();

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
const fail = (msg, status = 400) => Object.assign(new Error(msg), { status });
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => res.status(e.status || 500).json({ success: false, error: e.message }));

// AES-256-GCM so a leaked database row is useless without SESSION_SECRET
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
}
function decrypt(payload) {
  const [iv, tag, enc] = payload.split('.').map((s) => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

// Stateless per-user token handed out at login; required on every other call
const tokenFor = (u) => crypto.createHmac('sha256', KEY).update(u).digest('hex');
function auth(req, res, next) {
  const u = String(req.body.username || '').toLowerCase().trim();
  const given = Buffer.from(String(req.get('x-auth-token') || ''));
  const expected = Buffer.from(tokenFor(u));
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return res.status(401).json({ success: false, error: 'Unauthorized. Please log in again.' });
  }
  req.username = u;
  next();
}

async function getClient(username) {
  const { data, error } = await supabase
    .from('user_sessions').select('encrypted_session, whitelist').eq('username', username).single();
  if (error || !data) throw fail('Session expired or not found. Please log in again.', 404);
  const ig = new IgApiClient(); // fresh client per request: no cross-user state
  await ig.state.deserialize(JSON.parse(decrypt(data.encrypted_session)));
  // keep saved sessions on the same modern app version as login
  ig.state.constants.APP_VERSION = '315.0.0.33.109';
  ig.state.constants.APP_VERSION_CODE = '564998083';
  return { ig, whitelist: data.whitelist || [] };
}

async function readFeed(feed) {
  let out = [];
  do {
    out = out.concat(await feed.items());
    if (feed.isMoreAvailable()) await delay(800 + Math.random() * 700);
  } while (feed.isMoreAvailable());
  return out;
}

app.get('/', (req, res) => res.json({ ok: true }));

app.post('/api/login', wrap(async (req, res) => {
  const username = String(req.body.username || '').toLowerCase().trim();
  const password = req.body.password;
  if (!username || !password) throw fail('Username and password are required.');

  const ig = new IgApiClient();
  ig.state.generateDevice(username);
  ig.state.appVersion = '315.0.0.33.109';
  ig.state.userAgent = 'Instagram 315.0.0.33.109 Android (29/10; 480dpi; 1080x2280; OnePlus; ONEPLUS A6003; enchilada; qcom; en_US; 564998083)';
  // the library builds its own user agent from these constants, so set them too
  ig.state.constants.APP_VERSION = '315.0.0.33.109';
  ig.state.constants.APP_VERSION_CODE = '564998083';
  await ig.account.login(username, password); // password is never stored
  const session = await ig.state.serialize();
  delete session.constants;

  const { error } = await supabase.from('user_sessions').upsert(
    { username, encrypted_session: encrypt(JSON.stringify(session)), updated_at: new Date().toISOString() },
    { onConflict: 'username' }
  );
  if (error) throw error;
  res.json({ success: true, token: tokenFor(username), message: 'Logged in. Session backed up (encrypted).' });
}));

app.post('/api/analyze', auth, wrap(async (req, res) => {
  const { ig, whitelist } = await getClient(req.username);
  const id = ig.state.cookieUserId;
  const following = (await readFeed(ig.feed.accountFollowing(id))).map((u) => u.username);
  const followers = (await readFeed(ig.feed.accountFollowers(id))).map((u) => u.username);
  const followerSet = new Set(followers);
  const followingSet = new Set(following);
  res.json({
    success: true,
    nonFollowers: following.filter((u) => !followerSet.has(u)),
    fans: followers.filter((u) => !followingSet.has(u)),
    mutuals: following.filter((u) => followerSet.has(u)),
    whitelist,
  });
}));

app.post('/api/threads', auth, wrap(async (req, res) => {
  const { ig } = await getClient(req.username);
  const threads = await ig.feed.directInbox().items();
  res.json({
    success: true,
    threads: threads.map((t) => ({
      id: t.thread_id,
      title: t.thread_title || (t.users || []).map((u) => u.username).join(', ') || t.thread_id,
    })),
  });
}));

app.post('/api/unsend-chat', auth, wrap(async (req, res) => {
  const { targetThreadId } = req.body;
  const count = Math.min(Math.max(parseInt(req.body.messageCount, 10) || 5, 1), 10);
  if (!targetThreadId) throw fail('Target Thread ID is required.');

  const { ig } = await getClient(req.username);
  const items = await ig.feed.directThread({ thread_id: targetThreadId }).items();
  const mine = items.filter((i) => String(i.user_id) === String(ig.state.cookieUserId)).slice(0, count);

  let done = 0;
  for (const msg of mine) {
    await ig.directThread.deleteItem({ threadId: targetThreadId, itemId: msg.item_id });
    done++;
    if (done < mine.length) await delay(4000 + Math.floor(Math.random() * 4001));
  }
  res.json({ success: true, message: `Unsent ${done} of your recent messages in this chat.` });
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bridge engine running on port ${PORT}`));
