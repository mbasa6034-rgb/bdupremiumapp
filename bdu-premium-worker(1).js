// BDU PREMIUM — authentication helpers (Phase 1)
// Uses only Web Crypto, which is built into Cloudflare Workers.

const PBKDF2_ITERATIONS = 100000; // Cloudflare Workers caps PBKDF2 at 100k iterations
const SESSION_DAYS = 30;

const enc = new TextEncoder();

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function pbkdf2(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    key,
    256
  );
  return toHex(bits);
}

// Stored format: pbkdf2$<iterations>$<saltHex>$<hashHex>
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toHex(salt)}$${hash}`;
}

async function verifyPassword(password, stored) {
  const [scheme, iter, saltHex, expected] = stored.split('$');
  if (scheme !== 'pbkdf2') return false;
  const hash = await pbkdf2(password, fromHex(saltHex), Number(iter));
  // constant-time-ish comparison
  if (hash.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// Session tokens: the client gets a random token; the database stores only its SHA-256 hash.
async function createSession(db, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256Hex(token);
  const expires = new Date(Date.now() + SESSION_DAYS * 86400 * 1000).toISOString();
  await db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(tokenHash, userId, expires).run();
  return token;
}

async function getUserFromRequest(db, request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!match) return null;
  const tokenHash = await sha256Hex(match[1]);
  const row = await db.prepare(
    `SELECT u.id, u.full_name, u.university, u.campus, u.phone, u.is_suspended, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`
  ).bind(tokenHash).first();
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) return null;
  if (row.is_suspended) return null;
  return { id: row.id, full_name: row.full_name, university: row.university, campus: row.campus, phone: row.phone };
}

async function deleteSession(db, request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!match) return;
  await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(match[1])).run();
}

async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

// Simple fixed-window rate limiter stored in D1.
// Returns true if the action is allowed, false if the limit is exceeded.
async function allowRequest(db, bucket, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare('SELECT count, window_start FROM rate_limits WHERE bucket = ?')
    .bind(bucket).first();
  if (!row || now - row.window_start >= windowSeconds) {
    await db.prepare(
      'INSERT INTO rate_limits (bucket, count, window_start) VALUES (?, 1, ?) ' +
      'ON CONFLICT(bucket) DO UPDATE SET count = 1, window_start = excluded.window_start'
    ).bind(bucket, now).run();
    return true;
  }
  if (row.count >= limit) return false;
  await db.prepare('UPDATE rate_limits SET count = count + 1 WHERE bucket = ?').bind(bucket).run();
  return true;
}

// Ethiopian phone numbers: 09XXXXXXXX or 07XXXXXXXX, or +2519/+2517 forms.
// Returns normalized +251XXXXXXXXX or null if invalid.
function normalizePhone(input) {
  const digits = String(input || '').replace(/[\s-]/g, '');
  let m = digits.match(/^(?:\+?251|0)?([79]\d{8})$/);
  return m ? `+251${m[1]}` : null;
}

// BDU PREMIUM — Telegram helper (Phase 2: payment review)
// The bot token lives only in Cloudflare secrets (env.TELEGRAM_BOT_TOKEN).

function api(env, method) {
  return `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`;
}

function isAdmin(env, telegramId) {
  const ids = (env.TELEGRAM_ADMIN_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
  return ids.includes(String(telegramId));
}

// Sends the receipt photo to every admin with APPROVE / REJECT buttons.
async function sendPaymentReview(env, payment, student, receiptBlob) {
  const caption =
    'BDU PREMIUM — PAYMENT REVIEW\n\n' +
    `Student: ${student.full_name}\n` +
    `University: ${student.university}\n` +
    `Campus: ${student.campus}\n` +
    `Phone: ${student.phone}\n` +
    `Method: ${payment.method}\n` +
    `Reference: ${payment.reference}\n` +
    `Payment ID: ${payment.id}\n` +
    `Submitted: ${payment.created_at}`;

  const keyboard = {
    inline_keyboard: [[
      { text: 'APPROVE', callback_data: `approve:${payment.id}` },
      { text: 'REJECT', callback_data: `reject:${payment.id}` },
    ]],
  };

  const admins = (env.TELEGRAM_ADMIN_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const adminId of admins) {
    const form = new FormData();
    form.append('chat_id', adminId);
    form.append('caption', caption);
    form.append('reply_markup', JSON.stringify(keyboard));
    form.append('photo', receiptBlob, 'receipt.jpg');
    await fetch(api(env, 'sendPhoto'), { method: 'POST', body: form });
  }
}

async function answerCallback(env, callbackId, text) {
  await fetch(api(env, 'answerCallbackQuery'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: callbackId, text, show_alert: false }),
  });
}

// Removes the buttons once a decision is made, so nobody can press them twice.
async function markDecided(env, chatId, messageId, decisionText) {
  await fetch(api(env, 'editMessageCaption'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      caption: decisionText,
      reply_markup: { inline_keyboard: [] },
    }),
  });
}

// BDU PREMIUM — payments (Phase 2)
// Flow: student uploads receipt -> saved in D1 (pending) -> admin gets Telegram message
//       -> admin taps APPROVE or REJECT -> D1 updated -> entitlement granted if approved.

// Payment methods students can choose. Add/remove names here.
const METHODS = ['telebirr', 'cbe_birr', 'cbe_bank', 'bank_transfer'];
const MAX_RECEIPT_BYTES = 1024 * 1024; // 1 MB (receipts are stored inside the database)

// Converts image bytes to text so they can be stored in a database column.
function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

// Only real image files are accepted. We check the file's first bytes, not just its name.
function detectImageType(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return { ext: 'png', mime: 'image/png' };
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return { ext: 'webp', mime: 'image/webp' };
  return null;
}

// POST /api/receipt  (multipart form: method, reference, receipt=<image file>)
async function submitReceipt(request, env, cors, user) {
  if (!user) return json({ ok: false, error: 'Please log in first.' }, 401, cors);
  if (!await allowRequest(env.DB, `receipt:${user.id}`, 5, 3600)) {
    return json({ ok: false, error: 'Too many submissions. Try again later.' }, 429, cors);
  }

  const existing = await env.DB.prepare('SELECT premium FROM entitlements WHERE user_id = ?').bind(user.id).first();
  if (existing?.premium === 1) return json({ ok: false, error: 'You already have premium access.' }, 409, cors);

  const pending = await env.DB.prepare(
    "SELECT id FROM payments WHERE user_id = ? AND status = 'pending'"
  ).bind(user.id).first();
  if (pending) return json({ ok: false, error: 'You already have a payment waiting for review.' }, 409, cors);

  let form;
  try { form = await request.formData(); } catch { return json({ ok: false, error: 'Invalid upload.' }, 400, cors); }

  const method = String(form.get('method') || '');
  const reference = String(form.get('reference') || '').trim();
  const file = form.get('receipt');

  if (!METHODS.includes(method)) return json({ ok: false, error: 'Choose a valid payment method.' }, 400, cors);
  if (!/^[A-Za-z0-9]{4,40}$/.test(reference)) {
    return json({ ok: false, error: 'Enter the transaction reference (letters and numbers only).' }, 400, cors);
  }
  if (!file || typeof file === 'string') return json({ ok: false, error: 'Attach a receipt image.' }, 400, cors);
  if (file.size === 0 || file.size > MAX_RECEIPT_BYTES) {
    return json({ ok: false, error: 'Receipt must be an image under 1 MB. Try a smaller screenshot.' }, 400, cors);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  const type = detectImageType(bytes);
  if (!type) return json({ ok: false, error: 'Receipt must be a JPG, PNG or WEBP image.' }, 400, cors);

  const id = crypto.randomUUID();

  // Save the payment and its receipt together. If either fails, neither is saved.
  // The UNIQUE(method, reference) constraint blocks a transaction being used twice.
  try {
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO payments (id, user_id, method, reference, receipt_key) VALUES (?, ?, ?, ?, ?)'
      ).bind(id, user.id, method, reference, `db:${id}`),
      env.DB.prepare(
        'INSERT INTO receipts (payment_id, mime, data_base64) VALUES (?, ?, ?)'
      ).bind(id, type.mime, bytesToBase64(bytes)),
    ]);
  } catch {
    return json({ ok: false, error: 'This transaction reference was already submitted.' }, 409, cors);
  }

  const payment = await env.DB.prepare('SELECT id, method, reference, created_at FROM payments WHERE id = ?')
    .bind(id).first();
  const student = await env.DB.prepare('SELECT full_name, university, campus, phone FROM users WHERE id = ?')
    .bind(user.id).first();

  // Tell admins. If Telegram is down, the payment is still saved and can be seen later.
  try {
    await sendPaymentReview(env, payment, student, new Blob([bytes], { type: type.mime }));
  } catch (err) {
    console.error('Telegram notify failed', err && err.message);
  }

  return json({ ok: true, payment: { id, status: 'pending' } }, 201, cors);
}

// GET /api/payment/status  — the app polls this to learn the decision
async function paymentStatus(env, cors, user) {
  if (!user) return json({ ok: false, error: 'Please log in first.' }, 401, cors);
  const row = await env.DB.prepare(
    'SELECT id, status, created_at, decided_at FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(user.id).first();
  return json({ ok: true, payment: row ?? null }, 200, cors);
}

// POST /api/telegram/webhook  — Telegram calls this when an admin presses a button
async function telegramWebhook(request, env) {
  // Only requests carrying our secret header are accepted.
  if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_WEBHOOK_SECRET) {
    return new Response('Forbidden', { status: 403 });
  }
  const update = await request.json().catch(() => null);
  const cb = update?.callback_query;
  if (!cb) return new Response('ok');

  if (!isAdmin(env, cb.from.id)) {
    await answerCallback(env, cb.id, 'You are not authorized.');
    return new Response('ok');
  }

  const [action, paymentId] = String(cb.data || '').split(':');
  if (!paymentId || !['approve', 'reject'].includes(action)) {
    await answerCallback(env, cb.id, 'Unknown action.');
    return new Response('ok');
  }

  const newStatus = action === 'approve' ? 'approved' : 'rejected';
  const adminId = String(cb.from.id);

  // Only a pending payment can be decided. A second press changes nothing.
  const result = await env.DB.prepare(
    "UPDATE payments SET status = ?, decided_by = ?, decided_at = datetime('now') WHERE id = ? AND status = 'pending'"
  ).bind(newStatus, adminId, paymentId).run();

  if (!result.meta || result.meta.changes !== 1) {
    await answerCallback(env, cb.id, 'Already decided or not found.');
    return new Response('ok');
  }

  if (newStatus === 'approved') {
    const row = await env.DB.prepare('SELECT user_id FROM payments WHERE id = ?').bind(paymentId).first();
    await env.DB.prepare(
      `INSERT INTO entitlements (user_id, premium, granted_by_payment, updated_at)
       VALUES (?, 1, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET premium = 1, granted_by_payment = excluded.granted_by_payment, updated_at = datetime('now')`
    ).bind(row.user_id, paymentId).run();
  }

  const label = newStatus === 'approved' ? 'APPROVED' : 'REJECTED';
  await answerCallback(env, cb.id, `Payment ${label}.`);
  await markDecided(env, cb.message.chat.id, cb.message.message_id, `BDU PREMIUM — ${label} by admin ${adminId}`);
  return new Response('ok');
}


// BDU PREMIUM — Cloudflare Worker API (Phase 1: auth, content, premium checks)

// Only your own front-end origins may call the API from a browser.
// Set ALLOWED_ORIGINS in wrangler.toml [vars], comma-separated.
function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Vary': 'Origin',
  };
  if (allowed.includes(origin)) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

// Never leak internal details to the client; log them server-side without personal data.
function fail(status, message, cors) {
  return json({ ok: false, error: message }, status, cors);
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

// ---------- Auth ----------

async function signup(request, env, cors) {
  if (!await allowRequest(env.DB, `signup:${clientIp(request)}`, 5, 3600)) {
    return fail(429, 'Too many sign-up attempts. Try again later.', cors);
  }
  const body = await readJson(request);
  if (!body) return fail(400, 'Invalid request body.', cors);

  const fullName = String(body.full_name || '').trim();
  const university = String(body.university || '').trim();
  const campus = String(body.campus || '').trim();
  const phone = normalizePhone(body.phone);
  const password = String(body.password || '');
  const confirm = String(body.confirm_password || '');

  if (fullName.length < 3) return fail(400, 'Please enter your full name.', cors);
  if (!university || !campus) return fail(400, 'University and campus are required.', cors);
  if (!phone) return fail(400, 'Enter a valid Ethiopian phone number (e.g. 09XXXXXXXX).', cors);
  if (password.length < 8) return fail(400, 'Password must be at least 8 characters.', cors);
  if (password !== confirm) return fail(400, 'Passwords do not match.', cors);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE phone = ?').bind(phone).first();
  if (existing) return fail(409, 'This phone number is already registered.', cors);

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  await env.DB.prepare(
    'INSERT INTO users (id, full_name, university, campus, phone, password_hash) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, fullName, university, campus, phone, passwordHash).run();
  await env.DB.prepare('INSERT INTO entitlements (user_id, premium) VALUES (?, 0)').bind(id).run();

  const token = await createSession(env.DB, id);
  return json({ ok: true, token, user: { id, full_name: fullName, phone } }, 201, cors);
}

async function login(request, env, cors) {
  if (!await allowRequest(env.DB, `login:${clientIp(request)}`, 10, 900)) {
    return fail(429, 'Too many login attempts. Try again in 15 minutes.', cors);
  }
  const body = await readJson(request);
  const phone = normalizePhone(body?.phone);
  const password = String(body?.password || '');
  if (!phone || !password) return fail(400, 'Phone and password are required.', cors);

  const user = await env.DB.prepare(
    'SELECT id, full_name, password_hash, is_suspended FROM users WHERE phone = ?'
  ).bind(phone).first();
  // Same message whether the phone exists or not, to avoid account enumeration.
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return fail(401, 'Incorrect phone number or password.', cors);
  }
  if (user.is_suspended) return fail(403, 'This account is suspended. Contact support.', cors);

  const token = await createSession(env.DB, user.id);
  return json({ ok: true, token, user: { id: user.id, full_name: user.full_name, phone } }, 200, cors);
}

async function logout(request, env, cors) {
  await deleteSession(env.DB, request);
  return json({ ok: true }, 200, cors);
}

// ---------- Content (public reads, premium enforced server-side) ----------

async function getVersion(env, cors) {
  const row = await env.DB.prepare(
    'SELECT version, published_at FROM content_versions WHERE is_current = 1 ORDER BY id DESC LIMIT 1'
  ).first();
  return json({ ok: true, version: row?.version ?? '0', published_at: row?.published_at ?? null }, 200, cors);
}

async function getPrograms(env, cors) {
  const { results } = await env.DB.prepare('SELECT id, name FROM programs ORDER BY sort_order').all();
  return json({ ok: true, programs: results }, 200, cors);
}

async function getCourses(url, env, cors) {
  const semesterId = url.searchParams.get('semester');
  if (!semesterId) return fail(400, 'Missing semester parameter.', cors);
  const { results } = await env.DB.prepare(
    'SELECT id, name FROM courses WHERE semester_id = ? ORDER BY sort_order'
  ).bind(semesterId).all();
  return json({ ok: true, courses: results }, 200, cors);
}

async function getChapters(url, env, cors, user) {
  const courseId = url.searchParams.get('course');
  if (!courseId) return fail(400, 'Missing course parameter.', cors);
  const premium = user ? await hasPremium(env.DB, user.id) : false;
  const { results } = await env.DB.prepare(
    'SELECT id, number, title, is_free FROM chapters WHERE course_id = ? ORDER BY sort_order, number'
  ).bind(courseId).all();
  // Locked chapters are flagged; their content is never sent to non-premium users.
  const chapters = results.map((c) => ({
    ...c,
    locked: !c.is_free && !premium,
  }));
  return json({ ok: true, chapters }, 200, cors);
}

async function getNotes(url, env, cors, user) {
  const chapterId = url.searchParams.get('chapter');
  if (!chapterId) return fail(400, 'Missing chapter parameter.', cors);
  const chapter = await env.DB.prepare('SELECT id, is_free FROM chapters WHERE id = ?')
    .bind(chapterId).first();
  if (!chapter) return fail(404, 'Chapter not found.', cors);

  // The real gate: a locked chapter returns 402 without its content, regardless of what the UI shows.
  if (!chapter.is_free) {
    if (!user) return fail(401, 'Please log in to read this note.', cors);
    if (!(await hasPremium(env.DB, user.id))) {
      return fail(402, 'This chapter requires premium access.', cors);
    }
  }
  const note = await env.DB.prepare('SELECT body_html, updated_at FROM notes WHERE chapter_id = ?')
    .bind(chapterId).first();
  return json({ ok: true, note: note ?? { body_html: '', updated_at: null } }, 200, cors);
}

// ---------- Premium ----------

async function hasPremium(db, userId) {
  const row = await db.prepare('SELECT premium FROM entitlements WHERE user_id = ?').bind(userId).first();
  return row?.premium === 1;
}

async function premiumStatus(env, cors, user) {
  if (!user) return json({ ok: true, authenticated: false, premium: false }, 200, cors);
  return json({ ok: true, authenticated: true, premium: await hasPremium(env.DB, user.id) }, 200, cors);
}

// ---------- Router ----------

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      const path = url.pathname;
      const isGet = request.method === 'GET';
      const isPost = request.method === 'POST';

      // Auth
      // NOTE: every handler is "await"-ed so that errors reach the catch block below.
      if (isPost && path === '/api/auth/signup') return await signup(request, env, cors);
      if (isPost && path === '/api/auth/login') return await login(request, env, cors);
      if (isPost && path === '/api/auth/logout') return await logout(request, env, cors);

      // Public content
      if (isGet && path === '/api/version') return await getVersion(env, cors);
      if (isGet && path === '/api/programs') return await getPrograms(env, cors);

      // Telegram calls this directly. It is protected by its own secret header, not a login token.
      if (isPost && path === '/api/telegram/webhook') return await telegramWebhook(request, env);

      // Routes below use the logged-in user if a valid token is sent (optional for reads).
      const user = await getUserFromRequest(env.DB, request);

      // Payments (login required)
      if (isPost && path === '/api/receipt') return await submitReceipt(request, env, cors, user);
      if (isGet && path === '/api/payment/status') return await paymentStatus(env, cors, user);

      if (isGet && path === '/api/courses') return await getCourses(url, env, cors);
      if (isGet && path === '/api/chapters') return await getChapters(url, env, cors, user);
      if (isGet && path === '/api/notes') return await getNotes(url, env, cors, user);
      if (isGet && path === '/api/premium/status') return await premiumStatus(env, cors, user);

      return fail(404, 'Not found.', cors);
    } catch (err) {
      // Log the error for the developer; send the student a generic message.
      console.error('Unhandled error', err && err.message);
      return fail(500, 'Something went wrong. Please try again.', cors);
    }
  },
};
