// CyberAI Lab — посредник (прокси) к Groq для пользователей без своего ключа.
//
// Ключ Groq хранится в секрете GROQ_API_KEY на Cloudflare и никогда
// не попадает в программу. Посредник пропускает только чат с моделью
// CyberAI Lab и ограничивает число запросов с одного IP.
//
// Размещение: dash.cloudflare.com → Workers & Pages → Create → Worker →
// вставить этот код → Deploy → Settings → Variables and Secrets →
// Add → Type: Secret, Name: GROQ_API_KEY, Value: ключ gsk_... → Deploy.

const ALLOWED_MODELS = ["openai/gpt-oss-120b"];
const LIMIT_PER_IP = 30;              // запросов
const WINDOW_MS = 10 * 60 * 1000;     // за 10 минут
const MAX_TOKENS = 4096;

const hits = new Map();

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function error(message, status, type = "proxy_error") {
  return json({ error: { message, type } }, status);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response("CyberAI Lab AI proxy: OK");
    }

    if (request.method !== "POST" || url.pathname !== "/v1/chat/completions") {
      return error("Not found", 404);
    }

    if (request.headers.get("X-CyberAI-App") !== "1") {
      return error("Forbidden", 403);
    }

    if (!env.GROQ_API_KEY) {
      return error("На посреднике не задан секрет GROQ_API_KEY.", 500);
    }

    // Ограничение по IP (приблизительное — на каждый экземпляр посредника).
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const now = Date.now();
    const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);

    if (recent.length >= LIMIT_PER_IP) {
      return error(
        "Лимит общего ключа: подожди 10 минут или подключи свой бесплатный ключ Groq в Настройках.",
        429,
        "rate_limit_exceeded",
      );
    }

    recent.push(now);
    hits.set(ip, recent);

    if (hits.size > 10000) {
      hits.clear();
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return error("Bad JSON", 400);
    }

    if (!ALLOWED_MODELS.includes(body.model)) {
      return error("Model not allowed", 400);
    }

    body.max_completion_tokens = Math.min(
      Number(body.max_completion_tokens) || 1500,
      MAX_TOKENS,
    );
    delete body.max_tokens;

    const upstream = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.GROQ_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
    );

    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("Content-Type") || "application/json",
      },
    });
  },
};
