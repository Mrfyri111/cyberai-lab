// ============================================================
// CyberAI Cloud — сервер аккаунтов, почты и общего ИИ
// ============================================================
//
// Схема:  CyberAI_Lab.exe / сайт  →  этот сервер  →  Groq, Gmail
//
// - Аккаунты CyberAI Lab живут здесь (база Cloudflare D1). Один аккаунт
//   работает на любом компьютере и сразу даёт доступ к общему ИИ.
// - Регистрация и сброс пароля — с кодом на почту. Письма отправляет
//   сервер через SMTP (Gmail + пароль приложения).
// - Ключ Groq и пароль почты хранятся только в секретах Cloudflare.
//
// Привязки (Worker → Settings → Bindings):
//   DB             — D1 database (cyberai)
//   GROQ_API_KEY   — Secrets Store: ключ gsk_...
//   SMTP_USER      — Secrets Store: адрес Gmail, с которого идут письма
//   SMTP_PASSWORD  — Secrets Store: пароль приложения Gmail (16 букв)
// Или вместо Gmail — сервис рассылки Brevo (без пароля приложения):
//   BREVO_API_KEY  — Secrets Store: ключ xkeysib-... из Brevo
//   MAIL_FROM      — Secrets Store: почта отправителя, подтверждённая в Brevo
// Пока почты нет — тестовый режим (письма не отправляются, коды видны
// только владельцу в Cloudflare → Worker → Logs → Live):
//   MAIL_TEST      — Secrets Store или переменная: 1
// Таблицы создаются сами.
//
// Заблокировать пользователя: D1 → cyberai → Console:
//   UPDATE users SET banned = 1 WHERE username = 'логин';

const ALLOWED_MODELS = ["openai/gpt-oss-120b"];
const MAX_TOKENS = 4096;

const LIMIT_10_MIN = 30;          // сообщений ИИ за 10 минут на аккаунт
const LIMIT_DAY = 300;            // сообщений ИИ за сутки на аккаунт
const IP_LIMIT_10_MIN = 200;      // запасной лимит на IP (сайт — это один IP)
const REGISTRATIONS_PER_IP = 20;  // регистраций с одного IP за сутки
const LOGIN_FAILS = 5;            // неверных паролей → пауза 10 минут
const TOKEN_DAYS = 30;            // сколько живёт вход
const PBKDF2_ROUNDS = 10000;      // бесплатный тариф: ~10 мс CPU на запрос

const CODE_MINUTES = 10;          // код из письма действует 10 минут
const CODE_ATTEMPTS = 5;          // попыток ввода одного кода
const CODE_RESEND_SECONDS = 60;   // новый код — не чаще раза в минуту
const CODES_PER_HOUR = 5;         // писем на один адрес в час
const MAILS_PER_IP_HOUR = 30;     // писем с одного IP в час

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/;

// ------------------------------------------------------------
// Вспомогательное
// ------------------------------------------------------------

const encoder = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function fail(message, status, type = "cyberai_error") {
  return json({ error: { message, type } }, status);
}

function hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(bytes) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return hex(data);
}

function randomCode() {
  const data = new Uint32Array(1);
  crypto.getRandomValues(data);
  return String(data[0] % 1000000).padStart(6, "0");
}

async function sha256(text) {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ROUNDS },
    key,
    256,
  );
  return hex(bits);
}

function sameText(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function validUsername(username) {
  return USERNAME_RE.test(username)
    ? null
    : "Логин: 3–32 символа, латинские буквы, цифры и знаки _ . -";
}

function validEmail(email) {
  return email.length <= 254 && EMAIL_RE.test(email)
    ? null
    : "Похоже, почта написана с ошибкой (пример: name@gmail.com).";
}

function validPassword(password, username) {
  if (typeof password !== "string" || password.length < 8) {
    return "Пароль должен быть не короче 8 символов.";
  }
  if (password.length > 128) return "Пароль слишком длинный.";
  if (!/[A-Za-zА-Яа-яЁё]/.test(password) || !/\d/.test(password)) {
    return "Пароль должен содержать и буквы, и цифры.";
  }
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    return "Пароль не должен содержать логин.";
  }
  return null;
}

function maskEmail(email) {
  const [name, domain] = email.split("@");
  if (!domain) return email;
  const visible = name.length > 2 ? name.slice(0, 2) : name.slice(0, 1);
  return visible + "*".repeat(Math.max(2, name.length - visible.length)) + "@" + domain;
}

// Секрет: обычная строка или привязка Secrets Store (объект с get()).
async function secret(env, name) {
  const value = env[name];
  if (!value) return "";
  if (typeof value === "string") return value;
  if (typeof value.get === "function") {
    try {
      return (await value.get()) || "";
    } catch {
      return "";
    }
  }
  return "";
}

// ------------------------------------------------------------
// Почта: SMTP через TCP-сокет Cloudflare (Gmail, порт 465)
// ------------------------------------------------------------

function base64(text) {
  const bytes = encoder.encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function wrap76(text) {
  return text.match(/.{1,76}/g).join("\r\n");
}

const MAIL_TEXT = {
  register: [
    "Подтверждение регистрации",
    "Ты регистрируешься в CyberAI Lab. Введи этот код в программе:",
  ],
  reset: [
    "Восстановление пароля",
    "Кто-то (надеемся, ты) запросил сброс пароля в CyberAI Lab. Код:",
  ],
};

function buildMail(from, to, code, purpose) {
  const [title, text] = MAIL_TEXT[purpose] || MAIL_TEXT.register;
  const body =
    `${title}\r\n\r\n${text}\r\n\r\n    ${code}\r\n\r\n` +
    `Код действует ${CODE_MINUTES} минут. Никому его не сообщай.\r\n` +
    "Если ты ничего не запрашивал — просто проигнорируй это письмо.\r\n\r\n" +
    "— CyberAI Lab";

  return [
    `From: =?UTF-8?B?${base64("CyberAI Lab")}?= <${from}>`,
    `To: <${to}>`,
    `Subject: =?UTF-8?B?${base64(`${code} — ${title} | CyberAI Lab`)}?=`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomHex(12)}@cyberai.lab>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    wrap76(base64(body)),
  ].join("\r\n");
}

async function mailText(code, purpose) {
  const [title, text] = MAIL_TEXT[purpose] || MAIL_TEXT.register;
  return {
    subject: `${code} — ${title} | CyberAI Lab`,
    body:
      `${title}\n\n${text}\n\n    ${code}\n\n` +
      `Код действует ${CODE_MINUTES} минут. Никому его не сообщай.\n` +
      "Если ты ничего не запрашивал — просто проигнорируй это письмо.\n\n" +
      "— CyberAI Lab",
  };
}

// Brevo: письмо через HTTP API (бесплатно до 300 писем в день).
async function sendBrevo(env, key, to, code, purpose) {
  const from = await secret(env, "MAIL_FROM");
  if (!from) throw new Error("на сервере не задан MAIL_FROM (почта отправителя)");
  const { subject, body } = await mailText(code, purpose);
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": key, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      sender: { name: "CyberAI Lab", email: from },
      to: [{ email: to }],
      subject,
      textContent: body,
    }),
  });
  if (!response.ok) {
    const text = (await response.text()).slice(0, 200);
    throw new Error(`Brevo не отправил письмо (${response.status}): ${text}`);
  }
}

async function sendMail(env, to, code, purpose) {
  if ((await secret(env, "MAIL_TEST")) === "1") {
    console.log(`[ТЕСТ ПОЧТЫ] код ${code} для ${to} (${purpose})`);
    return;
  }

  const brevoKey = await secret(env, "BREVO_API_KEY");
  if (brevoKey) return sendBrevo(env, brevoKey, to, code, purpose);

  const user = await secret(env, "SMTP_USER");
  const password = (await secret(env, "SMTP_PASSWORD")).replace(/\s+/g, "");

  if (!user || !password) {
    throw new Error("на сервере не настроена почта (SMTP_USER, SMTP_PASSWORD)");
  }

  const connect = env.__connect || (await import("cloudflare:sockets")).connect;
  const socket = connect(
    { hostname: env.SMTP_HOST || "smtp.gmail.com", port: Number(env.SMTP_PORT || 465) },
    { secureTransport: "on", allowHalfOpen: false },
  );

  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  const decoder = new TextDecoder();
  let buffer = "";

  async function reply(expected) {
    // Ответ SMTP может быть многострочным: «250-...», последняя «250 ...».
    for (;;) {
      const lines = buffer.split("\r\n");
      for (let i = 0; i < lines.length - 1; i++) {
        if (/^\d{3} /.test(lines[i])) {
          const text = lines.slice(0, i + 1).join("\n");
          buffer = lines.slice(i + 1).join("\r\n");
          const code = Number(lines[i].slice(0, 3));
          if (code !== expected) throw new Error(`почтовый сервер: ${lines[i]}`);
          return text;
        }
      }
      const { value, done } = await reader.read();
      if (done) throw new Error("почтовый сервер закрыл соединение");
      buffer += decoder.decode(value, { stream: true });
    }
  }

  async function send(line, expected) {
    await writer.write(encoder.encode(line + "\r\n"));
    return reply(expected);
  }

  try {
    await reply(220);
    await send("EHLO cyberai.lab", 250);
    await send("AUTH LOGIN", 334);
    await send(base64(user), 334);
    try {
      await send(base64(password), 235);
    } catch {
      throw new Error("почта не приняла логин или пароль приложения");
    }
    await send(`MAIL FROM:<${user}>`, 250);
    await send(`RCPT TO:<${to}>`, 250);
    await send("DATA", 354);
    await send(buildMail(user, to, code, purpose) + "\r\n.", 250);
    await writer.write(encoder.encode("QUIT\r\n")).catch(() => {});
  } finally {
    try { await socket.close(); } catch { /* уже закрыт */ }
  }
}

// ------------------------------------------------------------
// База данных
// ------------------------------------------------------------

let schemaReady = false;

async function ensureSchema(db) {
  if (schemaReady) return;

  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      pass_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      banned INTEGER NOT NULL DEFAULT 0)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS tokens (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      ip TEXT,
      ts INTEGER NOT NULL)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_usage_user ON usage (user_id, ts)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_usage_ip ON usage (ip, ts)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      key TEXT NOT NULL,
      ts INTEGER NOT NULL)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_events ON events (kind, key, ts)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      payload TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used INTEGER NOT NULL DEFAULT 0)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_codes ON codes (email, purpose, id)`),
  ]);

  // Почта у пользователя (добавляется и в базы, созданные раньше).
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN email TEXT").run();
  } catch {
    // колонка уже есть
  }

  await db.prepare(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email) WHERE email IS NOT NULL",
  ).run();

  schemaReady = true;
}

async function countEvents(db, kind, key, since) {
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM events WHERE kind = ? AND key = ? AND ts >= ?")
    .bind(kind, key, since)
    .first();
  return row ? row.n : 0;
}

async function addEvent(db, kind, key) {
  await db.prepare("INSERT INTO events (kind, key, ts) VALUES (?, ?, ?)")
    .bind(kind, key, Date.now()).run();
}

async function issueToken(db, userId) {
  const token = randomHex(32);
  await db.prepare("INSERT INTO tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(await sha256(token), userId, Date.now() + TOKEN_DAYS * DAY).run();
  return token;
}

function bearer(request) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  return token && token.length <= 200 ? token : "";
}

async function userFromRequest(db, request) {
  const token = bearer(request);
  if (!token) return null;

  return db.prepare(
    `SELECT u.id, u.username, u.email, u.banned, u.created_at FROM tokens t
     JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.expires_at > ?`,
  ).bind(await sha256(token), Date.now()).first();
}

async function usageCounts(db, userId) {
  const now = Date.now();
  const row = await db.prepare(
    `SELECT
       SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS recent,
       COUNT(*) AS day
     FROM usage WHERE user_id = ? AND ts >= ?`,
  ).bind(now - 10 * MIN, userId, now - DAY).first();
  return { recent: (row && row.recent) || 0, day: (row && row.day) || 0 };
}

async function cleanup(db) {
  if (Math.random() > 0.02) return;
  const old = Date.now() - 2 * DAY;
  await db.batch([
    db.prepare("DELETE FROM usage WHERE ts < ?").bind(old),
    db.prepare("DELETE FROM events WHERE ts < ?").bind(old),
    db.prepare("DELETE FROM codes WHERE created_at < ?").bind(old),
    db.prepare("DELETE FROM tokens WHERE expires_at < ?").bind(Date.now()),
  ]);
}

function publicUser(user) {
  return {
    username: user.username,
    email: user.email || "",
    created_at: user.created_at || null,
  };
}

// ------------------------------------------------------------
// Коды подтверждения
// ------------------------------------------------------------

async function createCode(env, ip, email, purpose, payload) {
  const db = env.DB;
  const now = Date.now();

  const last = await db.prepare(
    "SELECT created_at FROM codes WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1",
  ).bind(email, purpose).first();

  if (last && now - last.created_at < CODE_RESEND_SECONDS * 1000) {
    const wait = Math.ceil((CODE_RESEND_SECONDS * 1000 - (now - last.created_at)) / 1000);
    return { error: `Новый код можно запросить через ${wait} с.`, status: 429 };
  }

  const perEmail = await db.prepare(
    "SELECT COUNT(*) AS n FROM codes WHERE email = ? AND created_at >= ?",
  ).bind(email, now - HOUR).first();

  if (perEmail && perEmail.n >= CODES_PER_HOUR) {
    return { error: "Слишком много писем на эту почту. Попробуй через час.", status: 429 };
  }

  if (await countEvents(db, "mail", ip, now - HOUR) >= MAILS_PER_IP_HOUR) {
    return { error: "Слишком много писем с этого компьютера. Попробуй позже.", status: 429 };
  }

  const code = randomCode();

  try {
    await sendMail(env, email, code, purpose);
  } catch (error) {
    return { error: `Не удалось отправить письмо: ${error.message}.`, status: 502 };
  }

  await db.batch([
    db.prepare("UPDATE codes SET used = 1 WHERE email = ? AND purpose = ?").bind(email, purpose),
    db.prepare(
      `INSERT INTO codes (email, purpose, code_hash, payload, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      email, purpose, await sha256(`${email}|${purpose}|${code}`),
      payload ? JSON.stringify(payload) : null, now, now + CODE_MINUTES * MIN,
    ),
  ]);

  await addEvent(db, "mail", ip);
  return { ok: true };
}

async function checkCode(db, email, purpose, code) {
  const row = await db.prepare(
    `SELECT * FROM codes WHERE email = ? AND purpose = ? AND used = 0
     ORDER BY id DESC LIMIT 1`,
  ).bind(email, purpose).first();

  if (!row) return { error: "Код не найден. Запроси новый." };
  if (row.expires_at < Date.now()) return { error: "Срок действия кода истёк. Запроси новый." };
  if (row.attempts >= CODE_ATTEMPTS) {
    return { error: "Слишком много неверных попыток. Запроси новый код." };
  }

  const expected = await sha256(`${email}|${purpose}|${String(code || "").replace(/\s/g, "")}`);

  if (!sameText(expected, row.code_hash)) {
    await db.prepare("UPDATE codes SET attempts = attempts + 1 WHERE id = ?").bind(row.id).run();
    const left = CODE_ATTEMPTS - row.attempts - 1;
    return {
      error: left > 0
        ? `Неверный код. Осталось попыток: ${left}.`
        : "Неверный код. Попытки закончились — запроси новый.",
    };
  }

  await db.prepare("UPDATE codes SET used = 1 WHERE id = ?").bind(row.id).run();
  return { ok: true, payload: row.payload ? JSON.parse(row.payload) : null };
}

// ------------------------------------------------------------
// Обработчики: аккаунты
// ------------------------------------------------------------

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// Шаг 1 регистрации: проверяем данные и отправляем код на почту.
async function registerStart(request, env, ip) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const username = String(body.username || "").trim();
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  const problem = validUsername(username) || validEmail(email) || validPassword(password, username);
  if (problem) return fail(problem, 400);

  const db = env.DB;

  if (await db.prepare("SELECT 1 FROM users WHERE username = ?").bind(username).first()) {
    return fail("Такой логин уже занят — придумай другой.", 409);
  }

  if (await db.prepare("SELECT 1 FROM users WHERE email = ?").bind(email).first()) {
    return fail("Эта почта уже зарегистрирована. Если это твой аккаунт — восстанови пароль.", 409);
  }

  if (await countEvents(db, "register", ip, Date.now() - DAY) >= REGISTRATIONS_PER_IP) {
    return fail("Слишком много регистраций с этого компьютера. Попробуй завтра.", 429);
  }

  const salt = randomHex(16);
  const result = await createCode(env, ip, email, "register", {
    username, salt, pass_hash: await hashPassword(password, salt),
  });

  if (result.error) return fail(result.error, result.status);
  return json({ sent: true, email: maskEmail(email) });
}

// Шаг 2 регистрации: код из письма → аккаунт создан, вход выполнен.
async function registerConfirm(request, env, ip) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const email = normalizeEmail(body.email);
  const db = env.DB;
  const check = await checkCode(db, email, "register", body.code);

  if (check.error) return fail(check.error, 400);

  const data = check.payload || {};

  try {
    const result = await db.prepare(
      "INSERT INTO users (username, pass_hash, salt, created_at, email) VALUES (?, ?, ?, ?, ?)",
    ).bind(data.username, data.pass_hash, data.salt, Date.now(), email).run();

    await addEvent(db, "register", ip);

    const user = await db.prepare("SELECT * FROM users WHERE id = ?")
      .bind(result.meta.last_row_id).first();

    return json({ token: await issueToken(db, user.id), ...publicUser(user) });
  } catch (error) {
    if (String(error).includes("UNIQUE")) {
      return fail("Логин или почту только что занял кто-то другой. Начни заново.", 409);
    }
    throw error;
  }
}

async function login(request, env) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const loginName = String(body.login || body.username || "").trim();
  const password = String(body.password || "");
  const key = loginName.toLowerCase();
  const db = env.DB;

  if (await countEvents(db, "login_fail", key, Date.now() - 10 * MIN) >= LOGIN_FAILS) {
    return fail("Слишком много неудачных попыток. Подожди 10 минут.", 429);
  }

  const user = loginName.includes("@")
    ? await db.prepare("SELECT * FROM users WHERE email = ?").bind(normalizeEmail(loginName)).first()
    : await db.prepare("SELECT * FROM users WHERE username = ?").bind(loginName).first();

  // Хэшируем и для несуществующего логина — чтобы по времени ответа
  // нельзя было угадать, какие логины заняты.
  const actual = await hashPassword(password, user ? user.salt : "00".repeat(16));

  if (!user || !sameText(actual, user.pass_hash)) {
    await addEvent(db, "login_fail", key);
    return fail("Неверный логин или пароль.", 401);
  }

  if (user.banned) return fail("Аккаунт заблокирован.", 403);

  return json({ token: await issueToken(db, user.id), ...publicUser(user) });
}

// Сброс пароля, шаг 1: код на почту (ответ одинаковый, есть аккаунт или нет).
async function resetStart(request, env, ip) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const email = normalizeEmail(body.email);
  const problem = validEmail(email);
  if (problem) return fail(problem, 400);

  const user = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();

  if (user) {
    const result = await createCode(env, ip, email, "reset", null);
    if (result.error && result.status !== 502) return fail(result.error, result.status);
    if (result.error) return fail(result.error, 502);
  } else {
    await addEvent(env.DB, "mail", ip);
  }

  return json({ sent: true, email: maskEmail(email) });
}

// Сброс пароля, шаг 2: код + новый пароль. Все старые входы отменяются.
async function resetConfirm(request, env) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const db = env.DB;

  const user = await db.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  const problem = validPassword(password, user ? user.username : "");
  if (problem) return fail(problem, 400);

  const check = await checkCode(db, email, "reset", body.code);
  if (check.error || !user) return fail(check.error || "Неверный код.", 400);

  const salt = randomHex(16);

  await db.batch([
    db.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?")
      .bind(await hashPassword(password, salt), salt, user.id),
    db.prepare("DELETE FROM tokens WHERE user_id = ?").bind(user.id),
    db.prepare("DELETE FROM events WHERE kind = 'login_fail' AND key IN (?, ?)")
      .bind(user.username.toLowerCase(), email),
  ]);

  return json({ ok: true, username: user.username });
}

async function changePassword(request, env) {
  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти заново.", 401, "invalid_token");

  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const full = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();

  if (!sameText(await hashPassword(String(body.old_password || ""), full.salt), full.pass_hash)) {
    return fail("Текущий пароль указан неверно.", 400);
  }

  const problem = validPassword(String(body.new_password || ""), full.username);
  if (problem) return fail(problem, 400);

  const salt = randomHex(16);
  const currentHash = await sha256(bearer(request));

  await env.DB.batch([
    env.DB.prepare("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?")
      .bind(await hashPassword(String(body.new_password), salt), salt, user.id),
    // Выходим на всех других устройствах, текущий вход оставляем.
    env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?")
      .bind(user.id, currentHash),
  ]);

  return json({ ok: true });
}

async function logout(request, env) {
  const token = bearer(request);
  if (token) {
    await env.DB.prepare("DELETE FROM tokens WHERE token_hash = ?")
      .bind(await sha256(token)).run();
  }
  return json({ ok: true });
}

async function logoutOthers(request, env) {
  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти заново.", 401, "invalid_token");

  await env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?")
    .bind(user.id, await sha256(bearer(request))).run();

  return json({ ok: true });
}

async function me(request, env) {
  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти заново.", 401, "invalid_token");
  if (user.banned) return fail("Аккаунт заблокирован.", 403);

  const used = await usageCounts(env.DB, user.id);
  return json({
    ...publicUser(user),
    used_10_min: used.recent,
    used_day: used.day,
    limit_10_min: LIMIT_10_MIN,
    limit_day: LIMIT_DAY,
  });
}

// ------------------------------------------------------------
// Общий ИИ
// ------------------------------------------------------------

async function chat(request, env, ip) {
  const apiKey = await secret(env, "GROQ_API_KEY");

  if (!apiKey) return fail("На сервере не задан секрет GROQ_API_KEY.", 500);

  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти в аккаунт заново.", 401, "invalid_token");
  if (user.banned) return fail("Аккаунт заблокирован.", 403);

  const used = await usageCounts(env.DB, user.id);

  if (used.recent >= LIMIT_10_MIN) {
    return fail(
      `Лимит общего ключа: ${LIMIT_10_MIN} сообщений за 10 минут. Подожди немного или подключи свой ключ Groq.`,
      429, "rate_limit_exceeded",
    );
  }

  if (used.day >= LIMIT_DAY) {
    return fail(
      `Лимит общего ключа: ${LIMIT_DAY} сообщений в сутки. Продолжим завтра или подключи свой ключ Groq.`,
      429, "rate_limit_exceeded",
    );
  }

  const ipRow = await env.DB.prepare("SELECT COUNT(*) AS n FROM usage WHERE ip = ? AND ts >= ?")
    .bind(ip, Date.now() - 10 * MIN).first();

  if (ipRow && ipRow.n >= IP_LIMIT_10_MIN) {
    return fail("Лимит общего ключа для этого компьютера. Подожди 10 минут.", 429, "rate_limit_exceeded");
  }

  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);
  if (!ALLOWED_MODELS.includes(body.model)) return fail("Модель не разрешена.", 400);

  body.max_completion_tokens = Math.min(Number(body.max_completion_tokens) || 1500, MAX_TOKENS);
  delete body.max_tokens;
  body.stream = false;

  await env.DB.prepare("INSERT INTO usage (user_id, ip, ts) VALUES (?, ?, ?)")
    .bind(user.id, ip, Date.now()).run();

  const upstream = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("Content-Type") || "application/json" },
  });
}

// ------------------------------------------------------------
// Точка входа
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      const missing = [];
      if (!env.DB) missing.push("привязка D1 с именем DB");
      if (!(await secret(env, "GROQ_API_KEY"))) missing.push("секрет GROQ_API_KEY");
      const mailTest = (await secret(env, "MAIL_TEST")) === "1";
      if (mailTest) {
        // письма не нужны — коды пишутся в логи
      } else if (await secret(env, "BREVO_API_KEY")) {
        if (!(await secret(env, "MAIL_FROM"))) missing.push("секрет MAIL_FROM");
      } else {
        if (!(await secret(env, "SMTP_USER"))) missing.push("секрет SMTP_USER (или BREVO_API_KEY)");
        if (!(await secret(env, "SMTP_PASSWORD"))) missing.push("секрет SMTP_PASSWORD (или BREVO_API_KEY)");
      }
      return new Response(
        missing.length
          ? "CyberAI Cloud: не настроено — нужны: " + missing.join(", ")
          : mailTest
            ? "CyberAI Cloud: OK (тестовый режим почты: коды в Logs)"
            : "CyberAI Cloud: OK",
        { headers: { "Content-Type": "text/plain; charset=utf-8" } },
      );
    }

    const isMe = request.method === "GET" && url.pathname === "/api/me";

    if (request.method !== "POST" && !isMe) return fail("Not found", 404);
    if (request.headers.get("X-CyberAI-App") !== "1") return fail("Forbidden", 403);
    if (!env.DB) return fail("На сервере не подключена база D1 (привязка DB).", 500);

    await ensureSchema(env.DB);
    await cleanup(env.DB);

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    switch (url.pathname) {
      case "/api/register/start": return registerStart(request, env, ip);
      case "/api/register/confirm": return registerConfirm(request, env, ip);
      case "/api/login": return login(request, env);
      case "/api/reset/start": return resetStart(request, env, ip);
      case "/api/reset/confirm": return resetConfirm(request, env);
      case "/api/password": return changePassword(request, env);
      case "/api/logout": return logout(request, env);
      case "/api/logout-others": return logoutOthers(request, env);
      case "/api/me": return me(request, env);
      case "/v1/chat/completions": return chat(request, env, ip);
      default: return fail("Not found", 404);
    }
  },
};
