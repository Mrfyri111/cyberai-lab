// ============================================================
// CyberAI Cloud — сервер аккаунтов и общего ИИ для CyberAI Lab
// ============================================================
//
// Схема:  CyberAI_Lab.exe  →  этот сервер  →  Groq
//
// - Ключ Groq хранится в секрете GROQ_API_KEY и никогда не попадает
//   в программу.
// - Пользоваться общим ИИ можно только после входа в аккаунт
//   CyberAI Cloud; у каждого аккаунта свой лимит запросов.
// - Аккаунты лежат в бесплатной базе Cloudflare D1 (привязка DB).
//
// Размещение (dash.cloudflare.com, всё бесплатно):
//   1) Storage & Databases → D1 → Create → имя: cyberai
//   2) Workers & Pages → Create → Worker → вставить этот код → Deploy
//   3) Worker → Settings → Bindings → Add → D1 database →
//      Variable name: DB, база: cyberai → Deploy
//   4) Worker → Settings → Variables and Secrets → Add →
//      Secret, GROQ_API_KEY = ключ gsk_... → Deploy
//   Таблицы создаются сами при первом запросе.
//
// Заблокировать пользователя: D1 → cyberai → Console:
//   UPDATE users SET banned = 1 WHERE username = 'логин';

const ALLOWED_MODELS = ["openai/gpt-oss-120b"];
const MAX_TOKENS = 4096;

const LIMIT_10_MIN = 30;          // запросов к ИИ за 10 минут на аккаунт
const LIMIT_DAY = 300;            // запросов к ИИ за сутки на аккаунт
const IP_LIMIT_10_MIN = 60;       // запасной лимит на IP (все аккаунты)
const REGISTRATIONS_PER_IP = 5;   // регистраций с одного IP за сутки
const LOGIN_FAILS = 5;            // неверных паролей подряд → пауза
const TOKEN_DAYS = 30;            // сколько живёт вход
const PBKDF2_ROUNDS = 10000;      // бесплатный тариф: ~10 мс CPU на запрос

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;

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
  ]);

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

async function userFromRequest(db, request) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  if (!token || token.length > 200) return null;

  return db.prepare(
    `SELECT u.id, u.username, u.banned FROM tokens t
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
  // Изредка чистим старые записи, чтобы база не росла.
  if (Math.random() > 0.02) return;
  const old = Date.now() - 2 * DAY;
  await db.batch([
    db.prepare("DELETE FROM usage WHERE ts < ?").bind(old),
    db.prepare("DELETE FROM events WHERE ts < ?").bind(old),
    db.prepare("DELETE FROM tokens WHERE expires_at < ?").bind(Date.now()),
  ]);
}

// ------------------------------------------------------------
// Обработчики
// ------------------------------------------------------------

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function register(request, env, ip) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!USERNAME_RE.test(username)) {
    return fail("Логин: 3–32 символа, латинские буквы, цифры и знаки _ . -", 400);
  }

  const passwordError = validPassword(password, username);
  if (passwordError) return fail(passwordError, 400);

  if (await countEvents(env.DB, "register", ip, Date.now() - DAY) >= REGISTRATIONS_PER_IP) {
    return fail("Слишком много регистраций с этого компьютера. Попробуй завтра.", 429);
  }

  const salt = randomHex(16);
  const passHash = await hashPassword(password, salt);

  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (username, pass_hash, salt, created_at) VALUES (?, ?, ?, ?)",
    ).bind(username, passHash, salt, Date.now()).run();

    await addEvent(env.DB, "register", ip);

    const userId = result.meta.last_row_id;
    return json({ token: await issueToken(env.DB, userId), username });
  } catch (error) {
    if (String(error).includes("UNIQUE")) {
      return fail("Такой логин уже занят в CyberAI Cloud.", 409);
    }
    throw error;
  }
}

async function login(request, env) {
  const body = await readBody(request);
  if (!body) return fail("Неверный запрос.", 400);

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const generic = "Неверный логин или пароль.";

  if (await countEvents(env.DB, "login_fail", username.toLowerCase(), Date.now() - 10 * MIN) >= LOGIN_FAILS) {
    return fail("Слишком много неудачных попыток. Подожди 10 минут.", 429);
  }

  const user = await env.DB.prepare(
    "SELECT id, username, pass_hash, salt, banned FROM users WHERE username = ?",
  ).bind(username).first();

  // Хэшируем и для несуществующего логина — чтобы по времени ответа
  // нельзя было угадать, какие логины заняты.
  const actual = await hashPassword(password, user ? user.salt : "00".repeat(16));

  if (!user || !sameText(actual, user.pass_hash)) {
    await addEvent(env.DB, "login_fail", username.toLowerCase());
    return fail(generic, 401);
  }

  if (user.banned) return fail("Аккаунт заблокирован.", 403);

  return json({ token: await issueToken(env.DB, user.id), username: user.username });
}

async function logout(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (token) {
    await env.DB.prepare("DELETE FROM tokens WHERE token_hash = ?")
      .bind(await sha256(token)).run();
  }
  return json({ ok: true });
}

async function me(request, env) {
  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти заново.", 401, "invalid_token");

  const used = await usageCounts(env.DB, user.id);
  return json({
    username: user.username,
    banned: !!user.banned,
    used_10_min: used.recent,
    used_day: used.day,
    limit_10_min: LIMIT_10_MIN,
    limit_day: LIMIT_DAY,
  });
}

async function chat(request, env, ip) {
  if (!env.GROQ_API_KEY) {
    return fail("На сервере не задан секрет GROQ_API_KEY.", 500);
  }

  const user = await userFromRequest(env.DB, request);
  if (!user) return fail("Нужно войти в аккаунт CyberAI Cloud заново.", 401, "invalid_token");
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
    headers: {
      Authorization: `Bearer ${env.GROQ_API_KEY}`,
      "Content-Type": "application/json",
    },
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
      const ready = env.DB && env.GROQ_API_KEY;
      return new Response(
        ready
          ? "CyberAI Cloud: OK"
          : "CyberAI Cloud: не настроено — нужны привязка D1 (DB) и секрет GROQ_API_KEY",
        { headers: { "Content-Type": "text/plain; charset=utf-8" } },
      );
    }

    if (request.method !== "POST" && !(request.method === "GET" && url.pathname === "/api/me")) {
      return fail("Not found", 404);
    }

    if (request.headers.get("X-CyberAI-App") !== "1") {
      return fail("Forbidden", 403);
    }

    if (!env.DB) {
      return fail("На сервере не подключена база D1 (привязка DB).", 500);
    }

    await ensureSchema(env.DB);
    await cleanup(env.DB);

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    switch (url.pathname) {
      case "/api/register": return register(request, env, ip);
      case "/api/login": return login(request, env);
      case "/api/logout": return logout(request, env);
      case "/api/me": return me(request, env);
      case "/v1/chat/completions": return chat(request, env, ip);
      default: return fail("Not found", 404);
    }
  },
};
