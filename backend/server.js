import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import OpenAI from 'openai';
import { query, withTransaction, closeDb } from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const OTP_EXPIRES_MS = Number(process.env.OTP_EXPIRES_MINUTES || 5) * 60 * 1000;
const SESSION_EXPIRES_MS = Number(process.env.SESSION_EXPIRES_DAYS || 30) * 24 * 60 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const OTP_IP_WINDOW_MS = 10 * 60 * 1000;
const OTP_IP_MAX_REQUESTS = 5;


async function sendFarazOtpSms(phone, code) {
  const apiKey = process.env.FARAZSMS_API_KEY;
  const patternCode = process.env.FARAZSMS_PATTERN_CODE;
  const lineNumber = process.env.FARAZSMS_LINE_NUMBER;

  if (!apiKey || !patternCode || !lineNumber) {
    throw new Error('تنظیمات FarazSMS کامل نیست.');
  }

  const response = await fetch('https://api.iranpayamak.com/ws/v1/sms/pattern', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Api-Key': apiKey,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      code: patternCode,
      attributes: {
        code
      },
      recipient: phone,
      line_number: lineNumber,
      number_format: 'english'
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`FarazSMS error: ${JSON.stringify(data)}`);
  }

  return data;
}
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(root, 'frontend')));

function normalizePhone(phone = '') {
  const p = String(phone).replace(/\D/g, '');
  return p.startsWith('9') ? `0${p}` : p;
}
function isIranPhone(phone) { return /^09\d{9}$/.test(phone); }
function generateOtp() { return String(crypto.randomInt(1000, 10000)); }
function createToken() { return crypto.randomBytes(32).toString('hex'); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

async function consumeOtpIpLimit(ip) {
  return withTransaction(async (client) => {
    const existing = await client.query(
      `SELECT window_started_at, request_count
         FROM otp_ip_rate_limits
        WHERE ip = $1
        FOR UPDATE`,
      [ip]
    );

    const now = new Date();
    const row = existing.rows[0];

    if (!row) {
      await client.query(
        `INSERT INTO otp_ip_rate_limits (ip, window_started_at, request_count)
         VALUES ($1, $2, 1)`,
        [ip, now]
      );
      return true;
    }

    const startedAt = new Date(row.window_started_at);
    if (now.getTime() - startedAt.getTime() >= OTP_IP_WINDOW_MS) {
      await client.query(
        `UPDATE otp_ip_rate_limits
            SET window_started_at = $2, request_count = 1
          WHERE ip = $1`,
        [ip, now]
      );
      return true;
    }

    if (Number(row.request_count) >= OTP_IP_MAX_REQUESTS) return false;

    await client.query(
      `UPDATE otp_ip_rate_limits
          SET request_count = request_count + 1
        WHERE ip = $1`,
      [ip]
    );
    return true;
  });
}

function defaultUserData() {
  return {
    theme: 'dark', notifications: true, bannerDismissed: false,
    tasks: [], habits: [
      { id: 'h1', name: 'مطالعه روزانه', icon: '📖', goal: '۳۰ دقیقه', log: {}, streak: 0 },
      { id: 'h2', name: 'ورزش', icon: '🏃', goal: '۲۰ دقیقه', log: {}, streak: 0 },
      { id: 'h3', name: 'نوشیدن آب', icon: '💧', goal: '۸ لیوان', log: {}, streak: 0 }
    ],
    focusSessions: {}, timer: { focus: 25, short: 5, long: 15, cycles: 4 }, discountEarned: false
  };
}
function ensureUserData(data) {
  const d = defaultUserData();
  const incoming = data && typeof data === 'object' ? data : {};
  return {
    ...d,
    ...incoming,
    timer: { ...d.timer, ...(incoming.timer || {}) },
    tasks: Array.isArray(incoming.tasks) ? incoming.tasks : d.tasks,
    habits: Array.isArray(incoming.habits) ? incoming.habits : d.habits,
    focusSessions: incoming.focusSessions && typeof incoming.focusSessions === 'object' ? incoming.focusSessions : {}
  };
}

async function cleanup() {
  await query('DELETE FROM otp_codes WHERE expires_at <= NOW() OR used = TRUE');
  await query('DELETE FROM sessions WHERE expires_at <= NOW()');
  await query('DELETE FROM otp_ip_rate_limits WHERE window_started_at <= NOW() - INTERVAL \'10 minutes\'');
}

async function auth(req, res, next) {
  try {
    const raw = req.headers.authorization || '';
    const value = raw.startsWith('Bearer ') ? raw.slice(7) : '';
    if (!value) return res.status(401).json({ error: 'احراز هویت لازم است.' });
    await cleanup();
    const { rows } = await query(
      `SELECT s.token_hash, s.user_id, s.expires_at,
              u.id, u.phone, u.name, u.email, u.goal, u.role, u.plan, u.created_at, u.data
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [sha256(value)]
    );
    const row = rows[0];
    if (!row) return res.status(401).json({ error: 'نشست شما معتبر نیست یا منقضی شده است.' });
    req.user = row;
    req.user.data = ensureUserData(row.data);
    req.rawToken = value;
    next();
  } catch (e) { next(e); }
}

function publicUser(row) {
  return {
    id: row.id,
    phone: row.phone,
    name: row.name,
    email: row.email,
    goal: row.goal,
    role: row.role,
    plan: row.plan,
    createdAt: row.created_at,
  };
}

async function getActiveSubscription(userId) {
  const result = await query(
    `SELECT plan, status, started_at, expires_at
     FROM subscriptions
     WHERE user_id = $1
       AND status = 'active'
       AND expires_at > NOW()
     ORDER BY expires_at DESC
     LIMIT 1`,
    [userId]
  );

  return result.rows[0] || null;
}

app.get('/api/health', async (_req, res, next) => {
  try {
    const { rows } = await query('SELECT NOW() AS now');
    res.json({ ok: true, app: 'زمانتو', version: '5.0.0', database: 'postgresql', time: rows[0].now });
  } catch (e) { next(e); }
});

app.post('/api/auth/request-otp', async (req, res, next) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    if (!isIranPhone(phone)) return res.status(400).json({ error: 'شماره موبایل باید ۱۱ رقمی و با 09 شروع شود.' });
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    if (!await consumeOtpIpLimit(ip)) {
      return res.status(429).json({ error: 'تعداد درخواست‌های کد تأیید از این اتصال بیش از حد مجاز است. کمی بعد دوباره تلاش کنید.' });
    }
    await cleanup();
    const recent = await query(
      `SELECT 1 FROM otp_codes WHERE phone = $1 AND created_at > NOW() - INTERVAL '60 seconds' LIMIT 1`,
      [phone]
    );
    if (recent.rowCount) return res.status(429).json({ error: 'لطفاً قبل از ارسال مجدد کمی صبر کنید.' });
    const code = generateOtp();
    const codeHash = sha256(code);
    await query(
      `INSERT INTO otp_codes (phone, code_hash, expires_at) VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 millisecond'))`,
      [phone, codeHash, OTP_EXPIRES_MS]
    );

    await sendFarazOtpSms(phone, code);

    
    const isDev = process.env.NODE_ENV !== 'production';
    if (isDev && process.env.OTP_MODE === 'console') {
      console.log(`[ZAMANETO OTP] ${phone} -> ${code}`);
    }
    const payload = { ok: true, expiresIn: Math.floor(OTP_EXPIRES_MS / 1000) };
    if (isDev && process.env.OTP_MODE === 'console') payload.devCode = code;
    res.json(payload);
  } catch (e) { next(e); }
});

app.post('/api/auth/verify-otp', async (req, res, next) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || '').replace(/\D/g, '');
    if (!isIranPhone(phone) || !/^\d{4}$/.test(code)) {
      return res.status(400).json({ error: 'شماره یا کد تأیید نامعتبر است.' });
    }

    const result = await withTransaction(async (client) => {
      const otpResult = await client.query(
        `SELECT id, code_hash, attempts FROM otp_codes
          WHERE phone = $1 AND used = FALSE AND expires_at > NOW()
          ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [phone]
      );
      const otp = otpResult.rows[0];
      if (!otp || otp.attempts >= OTP_MAX_ATTEMPTS) {
        throw Object.assign(new Error('OTP_INVALID'), { status: 401 });
      }

      if (otp.code_hash !== sha256(code)) {
        const attempts = otp.attempts + 1;
        await client.query('UPDATE otp_codes SET attempts = $1 WHERE id = $2', [attempts, otp.id]);
        throw Object.assign(new Error(attempts >= OTP_MAX_ATTEMPTS ? 'OTP_LOCKED' : 'OTP_INVALID'), { status: 401 });
      }

      await client.query('UPDATE otp_codes SET used = TRUE, used_at = NOW() WHERE id = $1', [otp.id]);
      let userResult = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
      let user = userResult.rows[0];
      if (!user) {
        userResult = await client.query(
          `INSERT INTO users (phone, name, email, goal, role, plan, data)
           VALUES ($1, '', '', '', 'ترکیبی', 'free', $2::jsonb)
           RETURNING *`, [phone, JSON.stringify(defaultUserData())]
        );
        user = userResult.rows[0];
      }

      const rawToken = createToken();
      await client.query(
        `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 millisecond'))`,
        [user.id, sha256(rawToken), SESSION_EXPIRES_MS]
      );
      return { user, rawToken };
    });

    res.json({ ok: true, token: result.rawToken, user: publicUser(result.user) });
  } catch (e) {
    if (e?.status === 401) {
      if (e?.message === 'OTP_LOCKED') return res.status(429).json({ error: 'تعداد تلاش‌های کد تأیید بیش از حد مجاز است. کد جدید درخواست کنید.' });
      return res.status(401).json({ error: 'کد تأیید اشتباه یا منقضی شده است.' });
    }
    next(e);
  }
});

app.get('/api/me', auth, async (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.put('/api/me', auth, async (req, res, next) => {
  try {
    const allowed = ['name', 'email', 'goal'];
    const values = {};
    for (const key of allowed) if (key in req.body) values[key] = String(req.body[key] ?? '').trim();
    const user = await query(
      `UPDATE users SET
         name = COALESCE($1, name), email = COALESCE($2, email),
         goal = COALESCE($3, goal), updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [values.name ?? null, values.email ?? null, values.goal ?? null, req.user.id]
    );
    res.json({ user: publicUser(user.rows[0]) });
  } catch (e) { next(e); }
});

app.get('/api/state', auth, async (req, res) => {
  res.json({ user: publicUser(req.user), data: ensureUserData(req.user.data) });
});

app.put('/api/state', auth, async (req, res, next) => {
  try {
    const incoming = req.body?.data || {};
    const current = ensureUserData(req.user.data);
    const allowed = ['theme', 'notifications', 'bannerDismissed', 'tasks', 'habits', 'focusSessions', 'timer', 'discountEarned'];
    for (const key of allowed) if (key in incoming) current[key] = incoming[key];
    const data = ensureUserData(current);
    const result = await query('UPDATE users SET data = $1::jsonb, updated_at = NOW() WHERE id = $2 RETURNING data', [JSON.stringify(data), req.user.id]);
    res.json({ ok: true, data: result.rows[0].data });
  } catch (e) { next(e); }
});

app.delete('/api/state', auth, async (req, res, next) => {
  try {
    const data = defaultUserData();
    const result = await query('UPDATE users SET data = $1::jsonb, updated_at = NOW() WHERE id = $2 RETURNING data', [JSON.stringify(data), req.user.id]);
    res.json({ ok: true, data: result.rows[0].data });
  } catch (e) { next(e); }
});

app.post('/api/auth/logout', auth, async (req, res, next) => {
  try {
    await query('DELETE FROM sessions WHERE token_hash = $1', [sha256(req.rawToken)]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/ai/suggest', auth, async (req, res, next) => {
  try {
    if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: 'OPENAI_API_KEY تنظیم نشده است.' });
    const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const context = req.body?.context || {};
    const prompt = `تو مربی بهره‌وری اپلیکیشن «زمانتو» هستی. بر اساس داده‌های کاربر یک پیشنهاد کوتاه و عملی به فارسی بده. خروجی فقط یک متن 2 تا 4 جمله‌ای باشد.\nداده‌ها:\n${JSON.stringify(context)}`;
    const response = await client.responses.create({ model: process.env.OPENAI_MODEL, input: prompt });
    res.json({ ok: true, text: response.output_text?.trim() || 'امروز فقط روی مهم‌ترین کار تمرکز کن.' });
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'خطای داخلی سرور.' });
});

app.get(/.*/, (_req, res) => res.sendFile(path.join(root, 'frontend', 'index.html')));

const server = app.listen(PORT, HOST, () => {
  console.log(`زمانتو روی http://${HOST}:${PORT} اجرا شد.`);
});

async function shutdown(signal) {
  console.log(`\n${signal} دریافت شد؛ سرور در حال خاموش شدن است...`);
  server.close(async () => {
    await closeDb();
    process.exit(0);
  });
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
