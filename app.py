import io
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

import openai
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from openai import OpenAI

import database
import demo_traffic
import mailer
from cyberai_engine import (
    CyberAIEngine,
    WINDOW_SECONDS,
    find_pktmon,
    find_tshark,
    is_admin,
    is_capture_device,
    is_loopback,
    list_interfaces,
    probe_interfaces,
)


# ============================================================
# CYBERAI LAB 11.0
# ============================================================

VERSION = "11.0"

st.set_page_config(
    page_title=f"CyberAI Lab {VERSION}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ss = st.session_state

GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_KEYS_URL = "https://console.groq.com/keys"

PAGES = [
    "📡 Мониторинг",
    "🚨 Центр угроз",
    "📄 Отчёты",
    "🤖 AI Assistant",
    "⚙️ Настройки",
]

AUTH_LOGIN = "🔐 Вход"
AUTH_REGISTER = "📝 Регистрация"
AUTH_RESET = "🔑 Забыл пароль"

# Графики показывают последние минуты — этого хватает для живого обзора.
RATE_MINUTES = 5
INTERVAL_MINUTES = 30

THREAT_FILTERS = {
    "Все": None,
    "🔴 Высокий": "ВЫСОКИЙ",
    "🟠 Средний": "СРЕДНИЙ",
    "🟡 Низкий": "НИЗКИЙ",
}

THREAT_SOURCES = ["Текущая сессия", "Последние 24 часа"]
REPORT_SOURCES = ["Текущая сессия", "Последние 24 часа", "Вся история"]

SEVERITY_ICON = {"ВЫСОКИЙ": "🔴", "СРЕДНИЙ": "🟠", "НИЗКИЙ": "🟡"}

SEVERITY_TITLE = {
    "ВЫСОКИЙ": "Опасная активность",
    "СРЕДНИЙ": "Подозрительная активность",
    "НИЗКИЙ": "Необычная активность",
}

STATUS_LABEL = {
    "НОРМА": "🟢 НОРМА",
    "АНОМАЛИЯ": "🔴 АНОМАЛИЯ",
    "ОБУЧЕНИЕ": "🔵 ОБУЧЕНИЕ",
}

NUMERIC_COLUMNS = [
    "Пакеты", "Байты", "SYN", "TCP", "UDP", "ICMP",
    "DNS", "ARP", "RST", "Источники", "Получатели", "Порты",
]

TABLE_COLUMNS = [
    "Время", "Статус", "Уровень", "Пакеты", "Байты", "SYN",
    "TCP", "UDP", "ICMP", "DNS", "ARP", "Порты",
    "Главный источник", "AI Score", "Причины",
]


# ============================================================
# DESIGN
# ============================================================

CONFIG_TOML = """# Создано CyberAI Lab автоматически.
[theme]
base = "dark"
primaryColor = "#3b82f6"
backgroundColor = "#0a1020"
secondaryBackgroundColor = "#162239"
textColor = "#e5eaf5"

[client]
toolbarMode = "minimal"
showSidebarNavigation = false

[browser]
gatherUsageStats = false
"""


SECRETS_TEMPLATE = """# Почта, с которой CyberAI Lab отправляет коды подтверждения.
# Заполни user и password, сохрани файл — и почта заработает.
# password — это «пароль приложения» Gmail (16 букв), НЕ обычный пароль.
# Получить: https://myaccount.google.com/apppasswords
# НИКОМУ не показывай и не выкладывай этот файл.

[email]
smtp_server = "smtp.gmail.com"
smtp_port = 465
user = ""
password = ""
sender_name = "CyberAI Lab"

# Необязательно: общий Groq-ключ, чтобы AI-чат работал у всех
# пользователей без своего ключа (например, на демо-сервере).
[groq]
api_key = ""
"""


def ensure_streamlit_config():
    """Создаёт .streamlit/config.toml рядом с app.py: тёмная тема
    с синими акцентами и без кнопки Deploy. Действует после
    перезапуска streamlit."""
    from pathlib import Path

    try:
        folder = Path(__file__).resolve().parent / ".streamlit"
        config = folder / "config.toml"

        if not config.exists():
            folder.mkdir(exist_ok=True)
            config.write_text(CONFIG_TOML, encoding="utf-8")

        secrets_file = folder / "secrets.toml"

        if not secrets_file.exists():
            secrets_file.write_text(SECRETS_TEMPLATE, encoding="utf-8")
    except Exception:
        pass


ensure_streamlit_config()

st.markdown("""
<style>
/* ---------- Основа ---------- */
.stApp {
    background:
        radial-gradient(1200px 600px at 85% -10%, rgba(59,130,246,0.10), transparent 60%),
        radial-gradient(900px 500px at -10% 110%, rgba(16,185,129,0.06), transparent 60%),
        #0a1020;
    color: #e5eaf5;
}

[data-testid="stMain"] {
    scroll-behavior: smooth;
}

.block-container {
    padding-top: 2.2rem;
}

/* ---------- Убираем Deploy, меню ⋮ и лишнее ---------- */
[data-testid="stToolbar"],
[data-testid="stAppDeployButton"],
[data-testid="stMainMenu"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
#MainMenu,
footer {
    display: none !important;
}

[data-testid="stHeader"] {
    background: transparent !important;
}

/* Встроенная стрелка Streamlit не нужна — есть своя кнопка ☰ */
[data-testid="stSidebarCollapseButton"] {
    display: none !important;
}

/* ---------- Без мигания при обновлении каждую секунду ---------- */
[data-stale="true"],
.stale-element,
[data-testid="stElementContainer"][data-stale="true"] {
    opacity: 1 !important;
    filter: none !important;
    transition: none !important;
}

/* ---------- Боковая панель: плавное скрытие ---------- */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #10192b 0%, #0d1526 100%);
    border-right: 1px solid #29344c;
    transition:
        width 0.35s cubic-bezier(.4,0,.2,1),
        min-width 0.35s cubic-bezier(.4,0,.2,1),
        max-width 0.35s cubic-bezier(.4,0,.2,1),
        opacity 0.25s ease,
        transform 0.35s cubic-bezier(.4,0,.2,1) !important;
}

/* Место под кнопку ⟨ в левом верхнем углу */
section[data-testid="stSidebar"] [data-testid="stSidebarContent"],
section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {
    padding-top: 2.6rem;
}

body.cy-sidebar-hidden section[data-testid="stSidebar"] {
    width: 0 !important;
    min-width: 0 !important;
    max-width: 0 !important;
    opacity: 0;
    transform: translateX(-30px);
    overflow: hidden !important;
    border-right: none;
}

/* ---------- Карточки метрик ---------- */
[data-testid="stMetric"] {
    background: linear-gradient(160deg, #182641 0%, #131f36 100%);
    border: 1px solid #2c3c57;
    border-radius: 16px;
    padding: 15px 18px;
    transition: transform 0.2s ease, border-color 0.2s ease,
                box-shadow 0.2s ease;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    border-color: #3b82f6;
    box-shadow: 0 10px 28px rgba(37, 99, 235, 0.18);
}

[data-testid="stMetricValue"] {
    transition: color 0.3s ease;
}

/* ---------- Контейнеры, карточки угроз ---------- */
[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 16px !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

[data-testid="stVerticalBlockBorderWrapper"]:hover {
    box-shadow: 0 8px 26px rgba(0, 0, 0, 0.25);
}

/* ---------- Чат ---------- */
[data-testid="stChatMessage"] {
    background: #142036;
    border: 1px solid #293a55;
    border-radius: 16px;
    max-width: 820px;
    margin-left: auto;
    margin-right: auto;
    animation: cy-fade-up 0.35s ease both;
}

[data-testid="stChatMessage"] table {
    font-size: 0.9rem;
}

[data-testid="stBottomBlockContainer"] {
    max-width: 860px;
    margin-left: auto;
    margin-right: auto;
}

@keyframes cy-fade-up {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* ---------- Кнопки ---------- */
div.stButton > button,
div.stDownloadButton > button,
div.stLinkButton > a,
div[data-testid="stFormSubmitButton"] > button {
    border-radius: 12px;
    min-height: 43px;
    transition: transform 0.15s ease, box-shadow 0.2s ease,
                background-color 0.2s ease, border-color 0.2s ease;
}

div.stButton > button:hover,
div.stDownloadButton > button:hover,
div[data-testid="stFormSubmitButton"] > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 18px rgba(37, 99, 235, 0.22);
}

div.stButton > button:active {
    transform: translateY(0);
}

div[data-testid="stSegmentedControl"] button {
    padding: 12px 18px;
    border-radius: 10px;
    transition: background-color 0.2s ease, color 0.2s ease,
                border-color 0.2s ease;
}

/* ---------- Поля ввода ---------- */
input, textarea {
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

/* ---------- Заголовок ---------- */
h1 {
    letter-spacing: -0.5px;
    text-shadow: 0 0 28px rgba(59, 130, 246, 0.25);
}

/* ---------- Полоса прокрутки ---------- */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
    background: #2a3a58;
    border-radius: 10px;
    border: 2px solid #0a1020;
}
::-webkit-scrollbar-thumb:hover { background: #3b4f75; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# КНОПКИ ☰ (ПАНЕЛЬ) И ↑ (НАВЕРХ)
# ============================================================

def inject_ui_helpers():
    components.html(
        """
        <script>
        (function () {
            try {
                const win = window.parent;
                const doc = win.document;
                const KEY = "cyberai_sidebar_hidden";

                function store(value) {
                    try { win.localStorage.setItem(KEY, value ? "1" : "0"); }
                    catch (e) {}
                }

                function stored() {
                    try { return win.localStorage.getItem(KEY) === "1"; }
                    catch (e) { return false; }
                }

                function styleButton(button, extra) {
                    Object.assign(button.style, {
                        position: "fixed",
                        borderRadius: "12px",
                        background: "rgba(22, 34, 57, 0.85)",
                        border: "1px solid #2c3c57",
                        color: "#e5eaf5",
                        cursor: "pointer",
                        zIndex: "2147483647",
                        backdropFilter: "blur(8px)",
                        boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
                        transition: "background 0.2s ease, transform 0.15s ease, border-color 0.2s ease",
                    }, extra);

                    button.addEventListener("mouseenter", function () {
                        button.style.background = "#2563eb";
                        button.style.borderColor = "#60a5fa";
                        button.style.transform = "translateY(-1px)";
                    });

                    button.addEventListener("mouseleave", function () {
                        button.style.background = "rgba(22, 34, 57, 0.85)";
                        button.style.borderColor = "#2c3c57";
                        button.style.transform = "none";
                    });
                }

                // ---------- ☰ Скрыть / показать панель ----------
                const oldToggle = doc.getElementById("cyberai-sidebar-toggle");
                if (oldToggle) { oldToggle.remove(); }

                if (doc.querySelector('section[data-testid="stSidebar"]')) {
                    const toggle = doc.createElement("button");
                    toggle.id = "cyberai-sidebar-toggle";
                    toggle.type = "button";

                    styleButton(toggle, {
                        left: "14px",
                        top: "14px",
                        width: "42px",
                        height: "42px",
                        fontSize: "20px",
                        lineHeight: "1",
                    });

                    function apply(hidden) {
                        doc.body.classList.toggle("cy-sidebar-hidden", hidden);
                        toggle.textContent = hidden ? "☰" : "⟨";
                        toggle.title = hidden ? "Показать панель" : "Скрыть панель";

                        // Графики подстраиваются под новую ширину.
                        setTimeout(function () {
                            win.dispatchEvent(new Event("resize"));
                        }, 380);
                    }

                    toggle.addEventListener("click", function (event) {
                        event.preventDefault();
                        const hidden = !doc.body.classList.contains("cy-sidebar-hidden");
                        store(hidden);
                        apply(hidden);
                    });

                    doc.body.appendChild(toggle);
                    apply(stored());
                }

                // ---------- ↑ Наверх ----------
                const oldButton = doc.getElementById("cyberai-scroll-top");
                if (oldButton) { oldButton.remove(); }

                const button = doc.createElement("button");
                button.id = "cyberai-scroll-top";
                button.type = "button";
                button.textContent = "↑";
                button.title = "Наверх";

                styleButton(button, {
                    right: "26px",
                    bottom: "105px",
                    width: "48px",
                    height: "48px",
                    borderRadius: "50%",
                    fontSize: "24px",
                    fontWeight: "bold",
                    opacity: "0",
                    pointerEvents: "none",
                });

                button.style.transition += ", opacity 0.25s ease";

                const main = doc.querySelector('[data-testid="stMain"]');

                function scroller() {
                    return main && main.scrollHeight > main.clientHeight
                        ? main : doc.scrollingElement;
                }

                // Кнопка появляется, только когда страница прокручена.
                function updateVisibility() {
                    const visible = scroller().scrollTop > 300;
                    button.style.opacity = visible ? "1" : "0";
                    button.style.pointerEvents = visible ? "auto" : "none";
                }

                if (main) { main.addEventListener("scroll", updateVisibility); }
                win.addEventListener("scroll", updateVisibility);

                button.addEventListener("click", function (event) {
                    event.preventDefault();
                    scroller().scrollTo({ top: 0, behavior: "smooth" });
                });

                doc.body.appendChild(button);
                updateVisibility();

            } catch (error) {
                console.error("CyberAI UI Error:", error);
            }
        })();
        </script>
        """,
        height=0,
    )


# ============================================================
# STORAGE & ENGINES (у каждого пользователя свой движок)
# ============================================================

@st.cache_resource
def init_storage():
    database.init_db()
    return True


@st.cache_resource
def engine_registry():
    return {"lock": threading.Lock(), "engines": {}}


def get_user_engine(user_id):
    registry = engine_registry()

    with registry["lock"]:
        engine = registry["engines"].get(user_id)

        if engine is None:
            def save(record, session_id, uid=user_id):
                database.save_interval(uid, session_id, record)

            def remember(rows, uid=user_id):
                database.save_baseline(uid, rows)

            engine = CyberAIEngine(on_record=save, on_fit=remember)
            registry["engines"][user_id] = engine

        return engine


def current_user():
    return ss.get("user")


def current_engine():
    user = current_user()

    if not user:
        return None

    return get_user_engine(user["id"])


def snapshot():
    engine = current_engine()

    if engine is None:
        return {"running": False, "history": []}

    try:
        result = engine.snapshot()
        return result if isinstance(result, dict) else {}

    except Exception as exc:
        return {"running": False, "history": [], "error": str(exc)}


# ============================================================
# HELPERS
# ============================================================

def history_of(data):
    history = data.get("history", [])

    if isinstance(history, pd.DataFrame):
        return history.to_dict("records")

    if isinstance(history, list):
        return [row for row in history if isinstance(row, dict)]

    return []


def num(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def pretty(value):
    return f"{int(num(value)):,}".replace(",", " ")


def pretty_bytes(value):
    """271300512 -> «271 МБ» — коротко, чтобы влезало в карточку."""
    size = num(value)

    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if abs(size) < 1000 or unit == "ГБ":
            if unit == "Б":
                return f"{int(size)} {unit}"
            text = f"{size:.1f}".replace(".", ",").removesuffix(",0")
            return f"{text} {unit}"
        size /= 1000

    return f"{size:.1f} ТБ"


def fmt_score(value):
    if value is None or value == "":
        return "—"

    try:
        return f"{float(value):.3f}"
    except (ValueError, TypeError):
        return "—"


def anomalies_of(history):
    return [
        row for row in history
        if str(row.get("Статус", "")).upper() == "АНОМАЛИЯ"
    ]


def get_stats(data):
    history = history_of(data)
    anomalies = anomalies_of(history)

    return {
        "running": bool(data.get("running", False)),
        "intervals": len(history),
        "anomalies": len(anomalies),
        "high": sum(
            1 for x in anomalies if x.get("Уровень") == "ВЫСОКИЙ"
        ),
        "packets": int(sum(num(x.get("Пакеты")) for x in history)),
        "bytes": int(sum(num(x.get("Байты")) for x in history)),
        "syn": int(sum(num(x.get("SYN")) for x in history)),
        "live_packets": int(num(data.get("live_packets"))),
        "live_bytes": int(num(data.get("live_bytes"))),
        "live_syn": int(num(data.get("live_syn"))),
        "training_count": int(num(data.get("training_count"))),
        "train_target": int(num(data.get("train_target"))) or 24,
        "trained": bool(data.get("trained")),
        "dropped": int(num(data.get("dropped"))),
        "error": data.get("error"),
        "save_error": data.get("save_error"),
        "raw_lines": int(num(data.get("raw_lines"))),
        "bad_lines": int(num(data.get("bad_lines"))),
        "last_bad_line": data.get("last_bad_line") or "",
        "current_rate": int(num(data.get("current_rate"))),
        "baseline_loaded": bool(data.get("baseline_loaded")),
    }


def history_frame(rows, minutes=None):
    df = pd.DataFrame(rows)

    if df.empty or "Метка" not in df.columns:
        return pd.DataFrame()

    df["Метка"] = pd.to_datetime(df["Метка"], errors="coerce")
    df = df.dropna(subset=["Метка"])

    for name in NUMERIC_COLUMNS:
        if name in df.columns:
            df[name] = pd.to_numeric(df[name], errors="coerce").fillna(0)

    if minutes and not df.empty:
        # От последней точки, а не от «сейчас» — так работают
        # и живой захват, и анализ старой записи.
        cutoff = df["Метка"].max() - timedelta(minutes=minutes)
        df = df[df["Метка"] >= cutoff]

    return df


# ============================================================
# AUTH
# ============================================================

COOKIE_NAME = "cyberai_session"


def set_browser_cookie(value, max_age):
    """Записывает cookie в браузер. Токен состоит только из
    безопасных символов (A-Z, a-z, 0-9, _ и -)."""
    value = re.sub(r"[^A-Za-z0-9_-]", "", value or "")

    components.html(
        f"""
        <script>
        try {{
            window.parent.document.cookie =
                "{COOKIE_NAME}={value}; path=/; "
                + "max-age={int(max_age)}; SameSite=Strict";
        }} catch (e) {{
            console.error("CyberAI cookie error:", e);
        }}
        </script>
        """,
        height=0,
    )


def read_browser_cookie():
    try:
        return st.context.cookies.get(COOKIE_NAME) or ""
    except Exception:
        return ""


def login(user, token=None):
    settings = database.get_settings(user["id"])

    ss.user = user
    ss.session_token = token
    ss.groq_key = settings["groq_key"]
    ss.chat_history = []
    ss.page = PAGES[0]
    ss.last_page = PAGES[0]
    ss.pdf_bytes = None


def try_restore_session():
    """После обновления страницы (F5) входит автоматически,
    если в браузере есть действующий токен «Запомнить меня»."""
    if current_user() or ss.get("skip_restore"):
        return

    token = read_browser_cookie()

    if not token:
        return

    user = database.get_session_user(token)

    if user:
        login(user, token=token)
    else:
        # Токен устарел или удалён — чистим cookie.
        ss.clear_cookie_pending = True


def logout():
    user = current_user()

    if user:
        engine = get_user_engine(user["id"])

        try:
            if engine.snapshot().get("running"):
                engine.stop()
        except Exception:
            pass

    database.delete_session(ss.get("session_token"))

    for key in [
        "user", "groq_key", "chat_history", "pdf_bytes",
        "pdf_source", "interfaces", "engine_msg", "session_token",
        "email_change", "reset_email", "reg_pending",
        "demo_code_register", "demo_code_change", "capture_source",
    ]:
        ss.pop(key, None)

    ss.clear_cookie_pending = True
    # Cookie в браузере удалится только после отрисовки страницы,
    # поэтому до конца этой вкладки не входим по нему снова.
    ss.skip_restore = True
    ss.auth_flash = "Ты вышел из аккаунта."


# ------------------------------------------------------------
# Защита от подбора пароля (брутфорса)
# ------------------------------------------------------------
# 1) С одного устройства — не больше LOGIN_MAX_FAILS неудачных
#    входов за LOGIN_WINDOW секунд, потом блокировка.
# 2) Каждая неудачная попытка отвечает всё медленнее.
# 3) Сам аккаунт блокируется на 5 минут после 5 ошибок
#    (это делает database.authenticate).

LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 10 * 60
REGISTER_MAX = 5


@st.cache_resource
def attempt_registry():
    return {"lock": threading.Lock(), "events": {}}


def client_key():
    """Кто подключается: IP посетителя (в облаке — из заголовка
    прокси). Если IP не виден — отдельный ключ на каждую вкладку,
    чтобы ограничения не срабатывали сразу для всех посетителей."""
    ip = None

    try:
        forwarded = st.context.headers.get("X-Forwarded-For") or ""
        ip = forwarded.split(",")[0].strip() or None
    except Exception:
        pass

    if not ip:
        try:
            ip = st.context.ip_address
        except Exception:
            ip = None

    if ip:
        return ip

    if "client_id" not in ss:
        import secrets as _secrets
        ss.client_id = "tab-" + _secrets.token_hex(8)

    return ss.client_id


def recent_events(key):
    registry = attempt_registry()
    now = time.time()

    with registry["lock"]:
        events = [
            t for t in registry["events"].get(key, [])
            if now - t < LOGIN_WINDOW
        ]
        registry["events"][key] = events
        return list(events)


def add_event(key):
    registry = attempt_registry()

    with registry["lock"]:
        registry["events"].setdefault(key, []).append(time.time())
        return len(registry["events"][key])


def clear_events(key):
    registry = attempt_registry()

    with registry["lock"]:
        registry["events"].pop(key, None)


def wait_text(seconds):
    seconds = max(1, int(seconds))
    minutes, sec = divmod(seconds, 60)

    if minutes:
        return f"{minutes} мин {sec} с"

    return f"{sec} с"


def login_block_left(key):
    events = recent_events("login:" + key)

    if len(events) < LOGIN_MAX_FAILS:
        return 0, LOGIN_MAX_FAILS - len(events)

    oldest = events[-LOGIN_MAX_FAILS]
    return LOGIN_WINDOW - (time.time() - oldest), 0


def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[a-zа-яё]", password) and re.search(r"[A-ZА-ЯЁ]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[^\w\s]", password):
        score += 1

    labels = [
        "очень слабый", "слабый", "слабый",
        "средний", "хороший", "отличный",
    ]

    return score, labels[score]


def render_login_form():
    key = client_key()
    wait, left = login_block_left(key)

    if wait > 0:
        st.error(
            "🔒 Слишком много неудачных попыток входа с этого "
            f"устройства. Попробуй через {wait_text(wait)}."
        )

    with st.form("login_form"):
        username = st.text_input("Логин или почта", key="login_username")
        password = st.text_input("Пароль", type="password")

        remember = st.checkbox(
            f"Запомнить меня на {database.SESSION_DAYS} дней",
            value=True,
            help="Не выкидывает из аккаунта при обновлении страницы. "
                 "Не включай на чужом компьютере.",
        )

        submitted = st.form_submit_button(
            "Войти",
            type="primary",
            width="stretch",
            disabled=wait > 0,
        )

    if submitted and wait <= 0:
        if not username.strip() or not password:
            st.error("Введи логин и пароль.")
        else:
            user, message = database.authenticate(username, password)

            if user:
                clear_events("login:" + key)
                ss.pop("skip_restore", None)

                token = None

                if remember:
                    token = database.create_session(user["id"])
                    ss.pending_cookie = token

                login(user, token=token)
                st.rerun()

            fails = add_event("login:" + key)

            # Каждая следующая ошибка — ответ медленнее.
            time.sleep(min(0.5 * fails, 3.0))

            left = max(0, LOGIN_MAX_FAILS - fails)

            if left:
                st.error(f"{message} Осталось попыток: {left}.")
            else:
                st.error(
                    "🔒 Вход с этого устройства заблокирован "
                    f"на {LOGIN_WINDOW // 60} минут."
                )

    left, right = st.columns(2)
    left.button(
        "📝 Создать аккаунт",
        width="stretch",
        on_click=set_auth_mode,
        args=(AUTH_REGISTER,),
        key="btn_to_register",
    )
    right.button(
        "🔑 Забыл пароль?",
        width="stretch",
        on_click=set_auth_mode,
        args=(AUTH_RESET,),
        key="btn_to_reset",
    )

    st.divider()

    if st.button(
        "👤 Войти как гость — без регистрации",
        width="stretch",
        key="btn_guest",
        help="Временный аккаунт, чтобы быстро посмотреть программу.",
    ):
        if len(recent_events("guest:" + key)) >= REGISTER_MAX:
            st.error("Слишком много гостевых входов. Попробуй позже.")
        else:
            user = database.create_guest_user()

            if user:
                add_event("guest:" + key)
                ss.pop("skip_restore", None)
                login(user)
                ss.capture_source = SOURCE_DEMO
                st.rerun()
            else:
                st.error("Не удалось создать гостевой аккаунт.")


MAIL_MAX_PER_DEVICE = 10


def set_auth_mode(mode):
    ss.auth_mode = mode


def codes_place():
    """Где владелец программы увидит код из демо-почты."""
    import sys

    if getattr(sys, "frozen", False):
        return "в файле **%LOCALAPPDATA%\\CyberAI Lab\\cyberai.log**"

    return "в **терминале**, где запущен `streamlit run app.py`"


def demo_hint(purpose):
    code = ss.get("demo_code_" + purpose)

    if mailer.is_demo() and code and purpose in ("register", "change"):
        st.info(
            f"🧪 **Демо-режим почты:** настоящие письма не отправляются. "
            f"Твой код: **{code}**"
        )
        return

    if mailer.is_demo() and purpose == "reset":
        st.info(
            "🧪 **Демо-режим почты:** письма не отправляются. Из "
            "соображений безопасности код сброса пароля показывается "
            "только владельцу программы — " + codes_place() + "."
        )
        return

    if not mailer.is_demo() and mailer.LAST_FALLBACK:
        st.warning(
            "⚠️ Письмо не отправилось (" + str(mailer.LAST_FALLBACK)
            + "). Код записан " + codes_place() + " — введи его оттуда."
        )
    elif mailer.is_demo():
        st.info(
            "🧪 **Демо-режим почты:** письмо не отправлялось — "
            "код записан " + codes_place() + "."
        )


def mail_limited(key):
    """Не больше MAIL_MAX_PER_DEVICE писем с одного устройства за 10 минут."""
    return len(recent_events("mail:" + key)) >= MAIL_MAX_PER_DEVICE


def send_code_to(email, purpose, key):
    """Создаёт код и отправляет письмо. Возвращает None или ошибку."""
    if mail_limited(key):
        return "Слишком много писем с этого устройства. Подожди 10 минут."

    code, error = database.create_email_code(email, purpose)

    if error:
        return error

    with st.spinner("Отправляю письмо..."):
        error = mailer.send_code(email, code, purpose)

    if not error:
        add_event("mail:" + key)

        # В демо-режиме код регистрации показываем на экране,
        # чтобы сайтом можно было пользоваться без почты.
        # Код сброса пароля — никогда (иначе любой сбросит чужой пароль).
        if mailer.is_demo() and purpose in ("register", "change"):
            ss["demo_code_" + purpose] = code

    return error


def render_register_form():
    key = client_key()
    use_mail = mailer.mail_configured()
    pending = ss.get("reg_pending")

    # ---------- Шаг 2: ввод кода из письма ----------
    if use_mail and pending:
        st.markdown(
            f"📨 Код отправлен на **{database.mask_email(pending['email'])}**. "
            "Проверь почту (и папку «Спам»)."
        )
        demo_hint("register")

        with st.form("reg_code_form"):
            code = st.text_input(
                "Код из письма",
                max_chars=database.CODE_LENGTH,
                placeholder="123456",
            )
            confirm = st.form_submit_button(
                "✅ Подтвердить и создать аккаунт",
                type="primary",
                width="stretch",
            )

        if confirm:
            ok, error = database.verify_email_code(
                pending["email"], "register", code
            )

            if not ok:
                st.error(error)
            else:
                ok, message = database.register_user(
                    pending["username"],
                    pending["password"],
                    pending["password"],
                    email=pending["email"],
                )

                if ok:
                    add_event("register:" + key)
                    ss.pop("reg_pending", None)
                    for name in ("reg_username", "reg_email",
                                 "reg_password", "reg_password2"):
                        ss.pop(name, None)
                    ss.auth_flash = message
                    ss.auth_mode_next = AUTH_LOGIN
                    ss.login_prefill = pending["username"]
                    st.rerun()
                else:
                    st.error(message)

        left, right = st.columns(2)

        if left.button("🔁 Отправить код ещё раз", width="stretch"):
            error = send_code_to(pending["email"], "register", key)

            if error:
                st.error(error)
            else:
                st.success("Новый код отправлен.")

        if right.button("← Изменить данные", width="stretch"):
            ss.pop("reg_pending", None)
            st.rerun()

        return

    # ---------- Шаг 1: данные аккаунта ----------
    username = st.text_input(
        "Придумай логин",
        key="reg_username",
        help="3–32 символа: латинские буквы, цифры, _ . -",
    )
    name = username.strip()
    name_ok = False

    if name:
        error = database.validate_username(name)

        if error:
            st.markdown(f":red[❌ {error}]")
        elif database.username_exists(name):
            st.markdown(
                f":red[❌ Логин «{name}» уже занят — придумай другой.]"
            )
        else:
            st.markdown(":green[✅ Логин свободен]")
            name_ok = True

    email = ""
    email_ok = not use_mail

    if use_mail:
        email = database.normalize_email(st.text_input(
            "Почта",
            key="reg_email",
            placeholder="name@gmail.com",
            help="На неё придёт код подтверждения. Через неё же "
                 "можно восстановить пароль.",
        ))

        if email:
            error = database.validate_email(email)

            if error:
                st.markdown(f":red[❌ {error}]")
            elif database.email_exists(email):
                st.markdown(
                    ":red[❌ Эта почта уже зарегистрирована. "
                    "Нажми «🔑 Забыл пароль», если это твой аккаунт.]"
                )
            else:
                st.markdown(":green[✅ Почта подходит]")
                email_ok = True

    password = st.text_input(
        "Придумай пароль",
        type="password",
        key="reg_password",
        help="Минимум 8 символов, буквы и цифры.",
    )

    if password:
        score, label = password_strength(password)
        st.progress(score / 5, text=f"Надёжность пароля: {label}")

    password2 = st.text_input(
        "Повтори пароль",
        type="password",
        key="reg_password2",
    )

    if password2 and password != password2:
        st.markdown(":red[❌ Пароли не совпадают]")

    st.caption("Проверка срабатывает после Enter или Tab.")

    button_text = (
        "📨 Получить код на почту" if use_mail else "Создать аккаунт"
    )

    if st.button(
        button_text,
        type="primary",
        width="stretch",
        disabled=(bool(name) and not name_ok)
                 or (bool(email) and not email_ok),
    ):
        if len(recent_events("register:" + key)) >= REGISTER_MAX:
            st.error(
                "Слишком много регистраций с этого устройства. "
                "Попробуй позже."
            )
            return

        if not use_mail:
            ok, message = database.register_user(name, password, password2)

            if ok:
                add_event("register:" + key)
                ss.auth_flash = message
                ss.auth_mode_next = AUTH_LOGIN
                ss.login_prefill = name
                st.rerun()
            else:
                st.error(message)
            return

        # Проверяем всё ДО отправки письма.
        error = (
            database.validate_username(name)
            or ("Логин уже занят." if database.username_exists(name) else None)
            or database.validate_email(email)
            or ("Почта уже зарегистрирована."
                if database.email_exists(email) else None)
            or ("Пароли не совпадают." if password != password2 else None)
            or database.validate_password(password, name)
        )

        if error:
            st.error(error)
            return

        error = send_code_to(email, "register", key)

        if error:
            st.error(error)
            return

        ss.reg_pending = {
            "username": name,
            "email": email,
            "password": password,
        }
        st.rerun()

    if use_mail:
        st.caption(
            "Пароль хранится только в виде хэша — "
            "даже владелец программы его не увидит."
        )
    else:
        st.caption(
            "📭 Отправка писем не настроена, поэтому регистрация без "
            "почты, а «Забыл пароль» недоступен."
        )


def render_reset_form():
    key = client_key()

    if not mailer.mail_configured():
        st.warning(
            "Восстановление по почте пока не настроено на этом "
            "компьютере. Владелец программы может включить его в "
            "файле .streamlit/secrets.toml."
        )
        return

    email = ss.get("reset_email")

    # ---------- Шаг 1: почта ----------
    if not email:
        st.markdown(
            "Введи почту, привязанную к аккаунту, — пришлём код "
            "для сброса пароля."
        )

        with st.form("reset_email_form"):
            value = st.text_input("Почта", placeholder="name@gmail.com")
            send = st.form_submit_button(
                "📨 Отправить код",
                type="primary",
                width="stretch",
            )

        if send:
            value = database.normalize_email(value)
            error = database.validate_email(value)

            if error:
                st.error(error)
                return

            # Не раскрываем, есть ли такой аккаунт: ответ всегда одинаковый.
            if database.get_user_by_email(value):
                error = send_code_to(value, "reset", key)

                if error:
                    st.error(error)
                    return
            else:
                add_event("mail:" + key)
                time.sleep(1.0)

            ss.reset_email = value
            st.rerun()

        return

    # ---------- Шаг 2: код + новый пароль ----------
    st.markdown(
        f"📨 Если почта **{database.mask_email(email)}** привязана к "
        "аккаунту, код уже в пути. Проверь и папку «Спам»."
    )
    demo_hint("reset")

    with st.form("reset_code_form"):
        code = st.text_input(
            "Код из письма",
            max_chars=database.CODE_LENGTH,
            placeholder="123456",
        )
        new = st.text_input("Новый пароль", type="password")
        new2 = st.text_input("Повтори новый пароль", type="password")
        submit = st.form_submit_button(
            "🔒 Сменить пароль",
            type="primary",
            width="stretch",
        )

    if submit:
        user = database.get_user_by_email(email)

        # Сначала проверяем пароль, чтобы не «сжечь» код зря.
        error = (
            ("Пароли не совпадают." if new != new2 else None)
            or database.validate_password(
                new, user["username"] if user else ""
            )
        )

        if error:
            st.error(error)
        else:
            ok, error = database.verify_email_code(email, "reset", code)

            if not ok or user is None:
                st.error(error or "Неверный код.")
            else:
                ok, message = database.reset_password_by_email(
                    email, new, new2
                )

                if ok:
                    clear_events("login:" + key)
                    ss.pop("reset_email", None)
                    ss.auth_flash = message
                    ss.auth_mode_next = AUTH_LOGIN
                    ss.login_prefill = user["username"]
                    st.rerun()
                else:
                    st.error(message)

    left, right = st.columns(2)

    if left.button("🔁 Отправить код ещё раз", width="stretch"):
        if database.get_user_by_email(email):
            error = send_code_to(email, "reset", key)
            if error:
                st.error(error)
            else:
                st.success("Новый код отправлен.")
        else:
            st.success("Новый код отправлен.")

    if right.button("← Другая почта", width="stretch"):
        ss.pop("reset_email", None)
        st.rerun()


def render_auth():
    # Переключение вкладки и подстановка логина
    # после успешной регистрации.
    if "auth_mode_next" in ss:
        ss.auth_mode = ss.pop("auth_mode_next")

    if "login_prefill" in ss:
        ss.login_username = ss.pop("login_prefill")

    if not ss.get("auth_mode"):
        ss.auth_mode = AUTH_LOGIN

    _, middle, _ = st.columns([1, 1.4, 1])

    with middle:
        st.title("🛡️ CyberAI Lab")
        st.caption(
            f"v{VERSION} • Интеллектуальный мониторинг "
            "и обнаружение аномалий сетевого трафика"
        )

        st.segmented_control(
            "Режим",
            options=[AUTH_LOGIN, AUTH_REGISTER, AUTH_RESET],
            key="auth_mode",
            selection_mode="single",
            label_visibility="collapsed",
            width="stretch",
        )

        mode = ss.auth_mode or AUTH_LOGIN

        flash = ss.pop("auth_flash", None)
        if flash:
            st.success(flash)

        if mode == AUTH_LOGIN:
            render_login_form()
        elif mode == AUTH_RESET:
            render_reset_form()
        else:
            render_register_form()

        st.info(
            "**Как проверить свой трафик:**\n\n"
            "🎬 **Демо** — посмотреть, как программа ловит атаки, "
            "ничего не устанавливая.\n\n"
            "📂 **Файл** — запиши трафик и загрузи его сюда: на Windows "
            "встроенной командой `pktmon` или в Wireshark, на Android — "
            "приложением PCAPdroid.\n\n"
            "📡 **Живой мониторинг** — только если запустить программу "
            "у себя на компьютере: браузер не даёт сайтам доступ "
            "к сетевой карте."
        )


# ============================================================
# NAVIGATION
# ============================================================

def init_session():
    defaults = {
        "page": PAGES[0],
        "last_page": PAGES[0],
        "groq_key": "",
        "chat_history": [],
        "threat_filter": "Все",
        "threat_source": THREAT_SOURCES[0],
        "report_source": REPORT_SOURCES[0],
    }

    for key, value in defaults.items():
        if key not in ss:
            ss[key] = value

    if ss.page not in PAGES:
        ss.page = ss.last_page if ss.last_page in PAGES else PAGES[0]


def on_nav_change():
    # Повторный клик по выбранной вкладке снимает выбор —
    # возвращаем последнюю открытую страницу.
    if ss.get("page") is None:
        ss.page = ss.get("last_page", PAGES[0])
    else:
        ss.last_page = ss.page


def go_to(page):
    ss.page = page
    ss.last_page = page


# ============================================================
# GROQ AI
# ============================================================

SYSTEM_PROMPT = """
Ты CyberAI — интеллектуальный помощник CyberAI Lab.

CyberAI Lab:
- захватывает сетевой трафик компьютера пользователя через TShark;
- анализирует трафик окнами по 5 секунд;
- обнаруживает подозрительную активность двумя способами:
  1) правила (сканирование портов, обход сети, SYN-flood, шторм RST,
     ICMP/DNS/ARP-флуд, смена MAC-адреса у IP — возможный ARP-спуфинг);
  2) Isolation Forest — машинное обучение на обычном трафике пользователя;
- присваивает уровни угрозы: НИЗКИЙ, СРЕДНИЙ, ВЫСОКИЙ;
- определяет, откуда трафик: IP-адрес, сайт (из DNS и HTTPS),
  понятный сервис (YouTube, Steam...) и программу на компьютере.
  Используй эти данные, чтобы объяснить, что вызвало аномалию.

Правила ответа:
- Отвечай понятно и естественно на русском языке, простыми словами.
- Если пользователь спрашивает про текущую сеть, используй только
  переданную фактическую статистику.
- Не выдумывай IP-адреса, пакеты или атаки.
- Аномалия — это отклонение от обычного поведения, а не доказательство
  атаки. Называй возможные безобидные причины (обновления, загрузки,
  игры, торренты, VPN, видеозвонки).
- Когда уместно, предлагай конкретные шаги проверки, например фильтры
  Wireshark.
- Если вопрос не связан с сетью, не вставляй сетевую статистику.
- Помогай защищать свои сети и устройства; не помогай атаковать чужие.
- Будь полезным, точным и конкретным.

Формат ответа (ВАЖНО):
- Пиши КОРОТКО: обычно 3–8 предложений или до 6 пунктов списка.
- Сначала главный вывод одной фразой («Всё нормально» / «Есть
  подозрительное: ...»), потом коротко детали и что сделать.
- НЕ используй таблицы, если пользователь сам не попросил таблицу.
- НЕ используй HTML-теги (<br>, <b> и т.п.) — только обычный Markdown.
- Не повторяй всю статистику — называй только важные цифры.
- Если пользователь просит «подробно» — тогда можно развёрнуто.
"""

DETAILED_PROMPT = (
    "Пользователь выбрал режим «Подробно»: можно отвечать развёрнуто, "
    "с разделами и списками, но всё равно без HTML-тегов."
)

ANSWER_STYLES = ["Коротко", "Подробно"]


def needs_network_data(question):
    words = [
        "трафик", "сеть", "сетев", "пакет", "аномал", "атак",
        "угроз", "монитор", "tcp", "udp", "syn", "tshark",
        "wireshark", "статистик", "байт", "безопасност",
        "isolation forest", "скан", "arp", "dns", "icmp", "порт",
    ]

    q = question.lower()
    return any(word in q for word in words)


def make_client(key):
    return OpenAI(
        api_key=key,
        base_url=GROQ_BASE_URL,
        timeout=60,
        max_retries=1,
    )


def make_proxy_client(url):
    return OpenAI(
        api_key="cyberai-proxy",
        base_url=url.rstrip("/") + "/v1",
        default_headers={"X-CyberAI-App": "1"},
        timeout=60,
        max_retries=1,
    )


def explain_ai_error(error):
    if "Лимит общего ключа" in str(error):
        return (
            "Лимит общего ключа: подожди 10 минут или подключи свой "
            "бесплатный ключ Groq в ⚙️ Настройках."
        )

    if isinstance(error, openai.AuthenticationError):
        return (
            "Неверный Groq API Key. Проверь, что скопировал "
            "его полностью (он начинается с gsk_)."
        )

    if isinstance(error, openai.PermissionDeniedError):
        return (
            "Groq отказал в доступе (403). Возможно, сервис "
            "недоступен в твоём регионе или ключ отключён."
        )

    if isinstance(error, openai.RateLimitError):
        return "Превышен лимит Groq. Подожди минуту и попробуй снова."

    if isinstance(error, openai.APIConnectionError):
        return (
            "Нет связи с Groq. Проверь интернет, VPN "
            "или брандмауэр."
        )

    if isinstance(error, openai.NotFoundError):
        return f"Модель {GROQ_MODEL} сейчас недоступна в Groq."

    text = str(error)
    lower = text.lower()

    if "invalid_api_key" in lower:
        return "Неверный Groq API Key."

    if "rate_limit" in lower:
        return "Превышен лимит Groq. Попробуй позже."

    if "model_not_found" in lower:
        return "Модель Groq недоступна."

    return text


def check_groq_key(key):
    try:
        make_client(key).models.list()
        return None
    except Exception as exc:
        return explain_ai_error(exc)


def network_context(data):
    history = history_of(data)
    stats = get_stats(data)

    keys = [
        "Время", "Пакеты", "Байты", "SYN", "TCP", "UDP",
        "ICMP", "DNS", "ARP", "Статус", "Уровень", "AI Score",
    ]

    return {
        "window_seconds": WINDOW_SECONDS,
        "statistics": {
            name: stats[name]
            for name in (
                "running", "intervals", "anomalies", "high",
                "packets", "bytes", "syn", "trained",
            )
        },
        "current_talkers": [
            {k: t.get(k) for k in (
                "Сайт", "Сервис", "Адрес", "Программа", "Доля",
            )}
            for t in (data.get("latest_talkers") or [])
        ],
        "recent_intervals": [
            {k: row.get(k) for k in keys} for row in history[-12:]
        ],
        "recent_anomalies": [
            {
                **{k: row.get(k) for k in (
                    "Метка", "Уровень", "Причины", "AI Score",
                )},
                "Источники": [
                    {k: t.get(k) for k in (
                        "Сайт", "Сервис", "Адрес", "Программа", "Доля",
                    )}
                    for t in (row.get("Источники трафика") or [])[:3]
                ],
            }
            for row in anomalies_of(history)[-8:]
        ],
    }


def build_messages(question, data, force_network=False):
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    if ss.get("answer_style") == "Подробно":
        messages.append({"role": "system", "content": DETAILED_PROMPT})

    clean_history = [
        item for item in ss.chat_history if not item.get("error")
    ]

    for item in clean_history[-10:]:
        messages.append({
            "role": item["role"],
            "content": item["content"],
        })

    content = question

    if force_network or needs_network_data(question):
        content += (
            "\n\nАктуальные данные CyberAI Lab:\n"
            + json.dumps(
                network_context(data),
                ensure_ascii=False,
                default=str,
            )
        )

    messages.append({"role": "user", "content": content})
    return messages


def clean_answer(text):
    """Убирает HTML-теги, которые модель иногда вставляет в Markdown."""
    text = re.sub(r"<br\s*/?>", "\n", text or "", flags=re.IGNORECASE)
    text = re.sub(r"</?(b|i|strong|em|p|span|div)[^>]*>", "", text,
                  flags=re.IGNORECASE)
    return text.strip()


def server_groq_key():
    """Общий ключ владельца сервера (необязательно), из secrets.toml:
    [groq]
    api_key = "gsk_..."
    """
    try:
        section = st.secrets.get("groq") or {}
        return str(section.get("api_key") or "").strip()
    except Exception:
        return ""


SHARED_AI_LIMIT = 15  # сообщений за 10 минут на общем ключе

# Посредник (Cloudflare Worker) с ключом владельца — для тех, у кого
# нет своего ключа. Сам ключ в программу не попадает.
# Код посредника: proxy/groq-worker.js
DEFAULT_AI_PROXY_URL = ""


def ai_proxy_url():
    try:
        section = st.secrets.get("ai_proxy") or {}
        url = str(section.get("url") or "").strip()
    except Exception:
        url = ""

    return url or os.environ.get("CYBERAI_AI_PROXY", "").strip() \
        or DEFAULT_AI_PROXY_URL


def ai_mode():
    """own — свой ключ; server — общий ключ сайта; proxy — посредник."""
    if (ss.get("groq_key") or "").strip():
        return "own"
    if server_groq_key():
        return "server"
    if ai_proxy_url():
        return "proxy"
    return ""


def active_groq_key():
    return (ss.get("groq_key") or "").strip() or server_groq_key()


def ai_available():
    return bool(ai_mode())


def ask_ai(question, data, force_network=False):
    mode = ai_mode()

    if not mode:
        raise ValueError("Подключи Groq API Key в ⚙️ Настройках.")

    detailed = ss.get("answer_style") == "Подробно"

    client = (
        make_proxy_client(ai_proxy_url()) if mode == "proxy"
        else make_client(active_groq_key())
    )

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=build_messages(question, data, force_network),
        temperature=0.4,
        max_completion_tokens=4096 if detailed else 1500,
        reasoning_effort="low",
    )

    return clean_answer(response.choices[0].message.content or "")


def scroll_to_last_answer():
    """Прокручивает к НАЧАЛУ нового ответа, а не в самый низ."""
    ss.scroll_counter = ss.get("scroll_counter", 0) + 1

    components.html(
        f"""
        <script>
        // {ss.scroll_counter}
        setTimeout(function () {{
            try {{
                const doc = window.parent.document;
                const items = doc.querySelectorAll(
                    '[data-testid="stChatMessage"]'
                );
                if (items.length) {{
                    items[items.length - 1].scrollIntoView({{
                        block: "start", behavior: "smooth"
                    }});
                }}
            }} catch (e) {{}}
        }}, 150);
        </script>
        """,
        height=0,
    )


def render_groq_setup(prefix, user):
    st.markdown("#### 🔑 Как получить бесплатный Groq API Key")

    st.markdown(
        "1. Нажми кнопку ниже — откроется **console.groq.com/keys**.\n"
        "2. Войди или зарегистрируйся (через Google, GitHub или почту). "
        "Это бесплатно.\n"
        "3. Нажми **Create API Key**, придумай название, например "
        "`CyberAI Lab`, и нажми **Submit**.\n"
        "4. **Сразу скопируй ключ** — он начинается с `gsk_`. "
        "Groq показывает его только один раз.\n"
        "5. Вставь ключ в поле ниже и нажми **Проверить и сохранить**."
    )

    st.link_button(
        "🌐 Открыть console.groq.com/keys",
        GROQ_KEYS_URL,
        width="stretch",
    )

    with st.form(f"{prefix}_groq_form"):
        key = st.text_input(
            "Groq API Key",
            type="password",
            placeholder="gsk_...",
        )

        remember = st.checkbox(
            "Запомнить ключ в моём аккаунте (хранится зашифрованным)",
            value=True,
        )

        submitted = st.form_submit_button(
            "✅ Проверить и сохранить",
            type="primary",
            width="stretch",
        )

    if submitted:
        key = key.strip()

        if not key:
            st.error("Вставь ключ в поле.")
            return

        if not key.startswith("gsk_"):
            st.warning(
                "Ключ Groq обычно начинается с gsk_. Проверяю всё равно..."
            )

        with st.spinner("Проверяю ключ в Groq..."):
            error = check_groq_key(key)

        if error:
            st.error(error)
            return

        ss.groq_key = key
        database.save_settings(
            user["id"],
            groq_key=key if remember else "",
        )
        ss.groq_flash = "Ключ работает! Можно общаться с CyberAI. 🎉"
        st.rerun()


# ============================================================
# PDF REPORT
# ============================================================

def pdf_text(value):
    text = "—" if value is None else str(value)

    for old, new in (("→", "->"), ("×", "x"), ("≈", "~")):
        text = text.replace(old, new)

    return escape(text)


def create_pdf(history, meta):
    import os

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output = io.BytesIO()
    font = "Helvetica"

    if "CyberFont" in pdfmetrics.getRegisteredFontNames():
        font = "CyberFont"
    else:
        for path in [
            r"C:\Windows\Fonts\arial.ttf",
            r"C:\Windows\Fonts\calibri.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]:
            if os.path.isfile(path):
                try:
                    pdfmetrics.registerFont(TTFont("CyberFont", path))
                    font = "CyberFont"
                    break
                except Exception:
                    pass

    title_style = ParagraphStyle(
        "CyberTitle",
        fontName=font,
        fontSize=22,
        leading=28,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365e"),
    )

    heading_style = ParagraphStyle(
        "CyberHeading",
        fontName=font,
        fontSize=13,
        leading=18,
        textColor=colors.HexColor("#17365e"),
        spaceBefore=16,
        spaceAfter=9,
    )

    normal_style = ParagraphStyle(
        "CyberNormal",
        fontName=font,
        fontSize=9,
        leading=15,
    )

    cell_style = ParagraphStyle(
        "CyberCell",
        fontName=font,
        fontSize=7.5,
        leading=10,
    )

    stats = get_stats({"history": history, "running": meta.get("running")})
    anomalies = anomalies_of(history)

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=44,
        bottomMargin=42,
    )

    period = "—"
    if history:
        period = (
            f"{history[0].get('Метка', '—')} — "
            f"{history[-1].get('Метка', '—')}"
        )

    story = [
        Paragraph("CYBERAI LAB", title_style),
        Spacer(1, 8),
        Paragraph("Отчёт интеллектуального мониторинга сети", normal_style),
        Spacer(1, 15),
        Paragraph(
            "Дата: " + datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            normal_style,
        ),
        Paragraph(
            "Пользователь: " + pdf_text(meta.get("username")),
            normal_style,
        ),
        Paragraph(
            "Источник данных: " + pdf_text(meta.get("source")),
            normal_style,
        ),
        Paragraph(
            "Технологии: TShark + правила обнаружения + Isolation Forest",
            normal_style,
        ),
        Paragraph("01 / Общая статистика", heading_style),
    ]

    rows = [
        ["ПОКАЗАТЕЛЬ", "ЗНАЧЕНИЕ"],
        ["Мониторинг", "Активен" if stats["running"] else "Остановлен"],
        ["Период", period],
        ["Интервалов анализа", str(stats["intervals"])],
        ["Обработано пакетов", pretty(stats["packets"])],
        ["Объём трафика", pretty_bytes(stats["bytes"])],
        ["TCP SYN", pretty(stats["syn"])],
        ["Аномальных интервалов", str(stats["anomalies"])],
        ["Высокий уровень угрозы", str(stats["high"])],
    ]

    table = Table(rows, colWidths=[200, 311])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#eef3f9")],
        ),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d6dfeb")),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(table)

    story.append(Paragraph("02 / Динамика сетевого трафика", heading_style))

    if history:
        packets = [num(row.get("Пакеты")) for row in history]

        fig, ax = plt.subplots(figsize=(9, 3.1))
        ax.plot(range(len(packets)), packets, linewidth=2, color="#2563eb")

        positions = [
            i for i, row in enumerate(history)
            if str(row.get("Статус", "")).upper() == "АНОМАЛИЯ"
        ]

        if positions:
            ax.scatter(
                positions,
                [packets[i] for i in positions],
                color="#dc2626",
                s=45,
                zorder=5,
                label="Anomaly",
            )
            ax.legend()

        ax.set_title("Network traffic / packets per interval")
        ax.set_xlabel("Interval")
        ax.set_ylabel("Packets")
        ax.grid(alpha=0.2)
        fig.tight_layout()

        chart_buffer = io.BytesIO()
        fig.savefig(chart_buffer, format="png", dpi=150)
        plt.close(fig)
        chart_buffer.seek(0)

        story.append(Image(chart_buffer, width=490, height=170))
    else:
        story.append(Paragraph("Данных для графика пока нет.", normal_style))

    story.append(Paragraph("03 / Результаты анализа", heading_style))

    if not history:
        conclusion = "Недостаточно данных для анализа. Запустите мониторинг."
    elif anomalies:
        levels = {
            level: sum(1 for x in anomalies if x.get("Уровень") == level)
            for level in ("ВЫСОКИЙ", "СРЕДНИЙ", "НИЗКИЙ")
        }
        conclusion = (
            f"Обнаружено {len(anomalies)} аномальных интервалов "
            f"(высокий уровень: {levels['ВЫСОКИЙ']}, "
            f"средний: {levels['СРЕДНИЙ']}, "
            f"низкий: {levels['НИЗКИЙ']}). "
            "Рекомендуется дополнительный анализ в Wireshark. "
            "Аномалия не доказывает атаку."
        )
    else:
        conclusion = (
            "В сохранённых интервалах аномалии не обнаружены. "
            "Это не гарантирует отсутствия всех сетевых угроз."
        )

    story.append(Paragraph(conclusion, normal_style))

    story.append(Paragraph("04 / Обнаруженные аномалии", heading_style))

    if anomalies:
        anomaly_rows = [["Время", "Уровень", "Пакеты", "SYN", "Причины"]]

        for item in anomalies[-20:]:
            anomaly_rows.append([
                Paragraph(pdf_text(item.get("Метка") or item.get("Время")), cell_style),
                Paragraph(pdf_text(item.get("Уровень")), cell_style),
                Paragraph(pretty(item.get("Пакеты")), cell_style),
                Paragraph(pretty(item.get("SYN")), cell_style),
                Paragraph(
                    pdf_text(item.get("Причины") or "Отклонение по модели")
                    .replace(" | ", "<br/>"),
                    cell_style,
                ),
            ])

        anomaly_table = Table(
            anomaly_rows,
            colWidths=[80, 58, 52, 42, 279],
            repeatRows=1,
        )

        anomaly_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        story.append(anomaly_table)
    else:
        story.append(
            Paragraph("Аномальных интервалов в истории нет.", normal_style)
        )

    story.append(Paragraph("05 / Рекомендации", heading_style))

    for tip in [
        "Проверьте аномальные интервалы в Wireshark по времени из таблицы.",
        "Полезные фильтры: tcp.flags.syn == 1 && tcp.flags.ack == 0 "
        "(попытки соединений), arp.duplicate-address-detected "
        "(конфликт IP/MAC), dns, icmp.",
        "Держите Windows, браузер и прошивку роутера обновлёнными.",
        "Используйте надёжный пароль Wi-Fi и шифрование WPA2/WPA3.",
    ]:
        story.append(Paragraph("• " + pdf_text(tip), normal_style))

    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            "CyberAI Lab — Automated Network Anomaly Detection",
            normal_style,
        )
    )

    document.build(story)
    output.seek(0)
    return output.getvalue()


# ============================================================
# SIDEBAR
# ============================================================

SOURCE_LIVE = "📡 Мой ПК"
SOURCE_DEMO = "🎬 Демо"
SOURCE_FILE = "📂 Файл"
SOURCES = [SOURCE_LIVE, SOURCE_DEMO, SOURCE_FILE]

DEMO_SPEED = 3          # демо проигрывается в 3 раза быстрее
UPLOAD_LIMIT_MB = 100
RECORD_SECONDS = 60

# Скрипт для Windows: записывает трафик встроенной утилитой pktmon
# (есть в Windows 10 2004+ и Windows 11) — ничего ставить не нужно.
RECORD_BAT_LINES = [
    "@echo off",
    "chcp 65001 >nul",
    "title CyberAI Lab - запись трафика",
    "setlocal",
    "",
    ":: Запись трафика нужна с правами администратора",
    "net session >nul 2>&1",
    "if errorlevel 1 (",
    "  echo Запрашиваю права администратора...",
    "  powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
    "  exit /b",
    ")",
    "",
    "where pktmon >nul 2>&1",
    "if errorlevel 1 (",
    "  echo [!] В этой версии Windows нет pktmon. Нужна Windows 10 версии 2004+ или Windows 11.",
    "  pause",
    "  exit /b 1",
    ")",
    "",
    "for /f \"usebackq delims=\" %%D in (`powershell -NoProfile -Command \"[Environment]::GetFolderPath('Desktop')\"`) do set \"DESK=%%D\"",
    "set \"ETL=%TEMP%\\cyberai_trace.etl\"",
    "set \"OUT=%DESK%\\cyberai_trace.pcapng\"",
    "",
    "pktmon stop >nul 2>&1",
    "pktmon filter remove >nul 2>&1",
    "if exist \"%ETL%\" del /q \"%ETL%\"",
    "if exist \"%OUT%\" del /q \"%OUT%\"",
    "",
    "echo.",
    "echo  ==============================================",
    "echo    CyberAI Lab: запись трафика {seconds} секунд",
    "echo  ==============================================",
    "echo  Пользуйся интернетом как обычно: сайты, видео, игры.",
    "echo  Чтобы закончить раньше, нажми любую клавишу.",
    "echo.",
    "",
    ":: Пишем первые 300 байт пакета: заголовки и имена сайтов.",
    ":: Содержимое видео и загрузок не нужно - так файл в разы меньше.",
    "pktmon start --capture --comp nics --pkt-size 300 -f \"%ETL%\" >nul",
    "if errorlevel 1 (",
    "  echo [!] Не удалось запустить запись.",
    "  pause",
    "  exit /b 1",
    ")",
    "",
    "timeout /t {seconds}",
    "",
    "pktmon stop >nul",
    "echo  Сохраняю запись...",
    "pktmon etl2pcap \"%ETL%\" -o \"%OUT%\" >nul",
    "del /q \"%ETL%\" >nul 2>&1",
    "",
    "if exist \"%OUT%\" (",
    "  echo.",
    "  echo  Готово! На рабочем столе файл cyberai_trace.pcapng",
    "  echo  Загрузи его на сайт CyberAI Lab: Источник трафика - Файл - Старт.",
    "  explorer /select,\"%OUT%\"",
    ") else (",
    "  echo [!] Не удалось сохранить запись.",
    ")",
    "echo.",
    "pause",
]


def record_bat_bytes(seconds=RECORD_SECONDS):
    text = "\r\n".join(RECORD_BAT_LINES).replace("{seconds}", str(seconds))
    return (text + "\r\n").encode("utf-8")


def render_record_help():
    with st.expander("📼 Как записать свой трафик", expanded=True):
        st.markdown("**💻 Windows — без установки программ:**")

        st.download_button(
            "⬇️ Скачать запись для Windows",
            data=record_bat_bytes(),
            file_name="CyberAI_record_traffic.bat",
            mime="application/octet-stream",
            width="stretch",
            key="btn_record_bat",
        )

        st.markdown(
            "1. Открой скачанный файл двойным кликом.\n"
            "2. Нажми **«Да»** на вопрос о правах администратора.\n"
            f"3. {RECORD_SECONDS} секунд пользуйся интернетом как обычно.\n"
            "4. На рабочем столе появится **cyberai_trace.pcapng** — "
            "загрузи его ниже и нажми **▶ Старт**."
        )

        st.caption(
            "Если Windows покажет «Система Windows защитила ваш "
            "компьютер» — нажми «Подробнее» → «Выполнить в любом "
            "случае». Скрипт только записывает трафик встроенной "
            "утилитой pktmon и ничего не отправляет в интернет."
        )

        st.markdown(
            "**📱 Android:** приложение **PCAPdroid** (бесплатно, без root) "
            "→ Start → поработай с приложениями → Stop → сохрани "
            "файл .pcap и загрузи сюда."
        )


EXE_URL = (
    "https://github.com/Mrfyri111/cyberai-lab/releases/download/"
    "windows-latest/CyberAI_Lab.exe"
)


def tshark_ready(user):
    """Wireshark установлен и интерфейс выбран."""
    settings = database.get_settings(user["id"])
    path = settings["tshark_path"] or find_tshark()
    return bool(path) and os.path.isfile(path) and bool(settings["interface"])


def live_capture_available(user):
    return tshark_ready(user) or bool(find_pktmon())


def demo_pcap_path():
    path = database.DATA_DIR / "demo_traffic.pcap"

    if not path.exists():
        database.DATA_DIR.mkdir(parents=True, exist_ok=True)
        demo_traffic.write_demo_pcap(str(path))

    return str(path)


def render_source_picker(user):
    live_ok = live_capture_available(user)

    if ss.get("capture_source") not in SOURCES:
        ss.capture_source = SOURCE_LIVE if live_ok else SOURCE_DEMO

    st.segmented_control(
        "Источник трафика",
        options=SOURCES,
        key="capture_source",
        selection_mode="single",
        width="stretch",
    )

    source = ss.capture_source or SOURCE_DEMO

    if source == SOURCE_LIVE and not live_ok:
        st.caption(
            "⚠️ Живой мониторинг своего компьютера через сайт "
            "невозможен — браузер не даёт доступ к сети. Скачай "
            "программу: она работает на Windows 10/11 без Wireshark."
        )
        st.link_button(
            "💻 Скачать CyberAI Lab для Windows",
            EXE_URL,
            width="stretch",
        )
    elif source == SOURCE_LIVE and tshark_ready(user):
        st.caption("Живой захват трафика этого компьютера через TShark.")
    elif source == SOURCE_LIVE:
        st.caption(
            "Живой захват через встроенную утилиту Windows pktmon — "
            "Wireshark не нужен. Данные обновляются каждые ~5 секунд."
        )

        if not is_admin():
            st.warning(
                "Нужны права администратора: закрой программу и "
                "запусти её правой кнопкой → «Запуск от имени "
                "администратора»."
            )
    elif source == SOURCE_DEMO:
        st.caption(
            "Записанный трафик домашней сети с 4 атаками: "
            "сканирование портов, всплеск загрузки, ARP-спуфинг, "
            f"SYN-flood. Проигрывается ×{DEMO_SPEED} (~2 мин)."
        )
    else:
        render_record_help()

        uploaded = st.file_uploader(
            "Запись трафика (.pcap / .pcapng)",
            type=["pcap", "pcapng", "cap"],
            key="pcap_upload",
            help="Сохрани трафик в Wireshark (File → Save As) или "
                 "на Android через приложение PCAPdroid.",
        )

        if uploaded is not None:
            if uploaded.size > UPLOAD_LIMIT_MB * 1024 * 1024:
                st.error(f"Файл больше {UPLOAD_LIMIT_MB} МБ.")
                ss.pop("upload_path", None)
            else:
                folder = database.DATA_DIR / "uploads"
                folder.mkdir(parents=True, exist_ok=True)
                target = folder / f"user_{user['id']}.pcap"
                target.write_bytes(uploaded.getvalue())
                ss.upload_path = str(target)
                ss.upload_name = uploaded.name
        else:
            ss.pop("upload_path", None)


def start_capture(user, engine):
    source = ss.get("capture_source") or SOURCE_DEMO

    if source == SOURCE_DEMO:
        engine.start_replay(
            demo_pcap_path(),
            source="demo",
            speed=DEMO_SPEED,
            label="демо-трафик",
        )
    elif source == SOURCE_FILE:
        path = ss.get("upload_path")

        if not path:
            raise ValueError("Сначала загрузи файл .pcap или .pcapng.")

        engine.start_replay(
            path,
            source="file",
            speed=0,
            label=ss.get("upload_name") or "файл",
        )
    elif tshark_ready(user):
        settings = database.get_settings(user["id"])
        engine.start(
            settings["tshark_path"] or find_tshark(),
            settings["interface"],
            baseline=database.load_baseline(user["id"]),
        )
    elif find_pktmon():
        engine.start_pktmon(baseline=database.load_baseline(user["id"]))
    else:
        raise ValueError(
            "Живой захват здесь недоступен: нет ни Wireshark, ни pktmon. "
            "Выбери 🎬 Демо или 📂 Файл."
        )


@st.fragment(run_every="1s")
def sidebar_controls():
    user = current_user()

    if not user:
        return

    engine = current_engine()
    data = snapshot()

    running = bool(data.get("running"))
    stopping = bool(data.get("stopping"))

    if stopping:
        st.info("⏳ Останавливаю захват...")
    elif running:
        st.success("● Мониторинг активен")

        started = data.get("started_at")

        if data.get("source") in ("demo", "file"):
            st.progress(
                float(data.get("replay_progress") or 0),
                text=f"Проигрывается: {data.get('source_label')}",
            )
        elif isinstance(started, datetime):
            seconds = int((datetime.now() - started).total_seconds())
            st.caption(
                f"Источник: {data.get('interface')} • "
                f"работает {seconds // 60} мин {seconds % 60} с"
            )
    elif data.get("replay_finished"):
        st.success(f"✅ Запись проанализирована: {data.get('source_label')}")
    else:
        st.warning("● Мониторинг остановлен")

    col_start, col_stop = st.columns(2)

    with col_start:
        if st.button(
            "▶ Старт",
            width="stretch",
            disabled=running or stopping,
            key="btn_start",
        ):
            try:
                start_capture(user, engine)
                ss.engine_msg = ""
            except Exception as exc:
                ss.engine_msg = str(exc)

            st.rerun(scope="fragment")

    with col_stop:
        if st.button(
            "■ Стоп",
            width="stretch",
            disabled=not running or stopping,
            key="btn_stop",
        ):
            engine.stop()
            st.rerun(scope="fragment")

    if not running and not stopping:
        message = ss.get("engine_msg") or data.get("error")

        if message:
            st.error(message)

            if st.button(
                "⚙️ Открыть настройки",
                width="stretch",
                key="btn_open_settings",
                on_click=go_to,
                args=(PAGES[4],),
            ):
                st.rerun()


def render_sidebar(user):
    with st.sidebar:
        st.title("🛡️ CyberAI Lab")
        st.caption(f"LIVE EDITION • v{VERSION}")

        with st.container(border=True):
            st.markdown(f"👤 **{user['username']}**")
            st.caption("Твои данные хранятся отдельно от других.")
            st.button(
                "🚪 Выйти",
                on_click=logout,
                width="stretch",
                key="btn_logout",
            )

        st.divider()
        st.subheader("Управление мониторингом")
        render_source_picker(user)
        sidebar_controls()

        st.divider()
        st.subheader("🤖 Groq AI")

        if ss.get("groq_key"):
            st.success("Ключ подключён")
        elif ai_mode() in ("server", "proxy"):
            st.success("AI работает через общий ключ")
            st.caption("Можно подключить свой — в ⚙️ Настройках.")
        else:
            st.info("Ключ не указан")
            st.button(
                "🔑 Подключить Groq",
                width="stretch",
                on_click=go_to,
                args=(PAGES[3],),
                key="btn_sidebar_groq",
            )

        st.divider()
        st.caption("Capture: TShark / pcap")
        st.caption("Detection: Rules + Isolation Forest")
        st.caption("AI: Groq")



# ============================================================
# ОТКУДА ТРАФИК
# ============================================================

def talkers_frame(talkers):
    rows = []

    for item in talkers or []:
        site = item.get("Сайт") or "неизвестно"

        if item.get("Сервис"):
            site = f"{item['Сервис']} — {site}"

        rows.append({
            "Сайт / узел": site,
            "IP-адрес": item.get("Адрес", ""),
            "Программа": item.get("Программа") or "—",
            "Доля": f"{item.get('Доля', 0)}%",
            "Пакеты": int(num(item.get("Пакеты"))),
            "Байты": int(num(item.get("Байты"))),
            "Порты": item.get("Порты") or "—",
        })

    return pd.DataFrame(rows)


def render_talkers(data, running):
    st.subheader("🌐 С кем сейчас общается компьютер")

    talkers = data.get("latest_talkers") or []

    if not talkers:
        if running:
            st.info("Собираю данные... таблица появится через 5 секунд.")
        else:
            st.info("Запусти мониторинг, чтобы увидеть сайты и программы.")
        return

    st.dataframe(
        talkers_frame(talkers),
        width="stretch",
        hide_index=True,
    )

    tips = [
        "Обновляется каждые 5 секунд. «Неизвестно» — сайт был открыт "
        "до запуска мониторинга, его имя появится при следующем "
        "подключении."
    ]

    if not data.get("psutil"):
        tips.append(
            "Чтобы видеть программы, выполни `pip install psutil` "
            "и перезапусти."
        )

    st.caption(" ".join(tips))


# ============================================================
# PAGE: МОНИТОРИНГ
# ============================================================

@st.fragment(run_every="1s")
def live_monitor():
    if not current_user():
        return

    data = snapshot()
    history = history_of(data)
    stats = get_stats(data)

    running = stats["running"]
    started = data.get("started_at")
    elapsed = (
        int((datetime.now() - started).total_seconds())
        if running and isinstance(started, datetime) else 0
    )

    rates = data.get("rates") or []
    previous_rate = rates[-2]["Пакеты/с"] if len(rates) >= 2 else 0

    st.subheader("📊 Мониторинг в реальном времени")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Пакеты", pretty(stats["packets"] + stats["live_packets"]))
    m2.metric("Трафик", pretty_bytes(stats["bytes"] + stats["live_bytes"]))
    m3.metric(
        "⚡ Скорость",
        f"{pretty(stats['current_rate'])} пак/с",
        delta=(
            stats["current_rate"] - previous_rate
            if len(rates) >= 2 else None
        ),
    )
    m4.metric("TCP SYN", pretty(stats["syn"] + stats["live_syn"]))
    m5.metric("Аномалии", stats["anomalies"])

    target = stats["train_target"]
    trained_count = min(stats["training_count"], target)

    m6, m7, m8, m9 = st.columns(4)
    m6.metric("Интервалы", stats["intervals"])
    is_file = data.get("source") == "file"

    if is_file and data.get("replay_finished"):
        model_text = "Проверено ✅" if stats["trained"] else "Только правила"
    elif is_file and running:
        model_text = "Читаю файл…"
    elif stats["trained"]:
        model_text = "Готова ✅"
    else:
        model_text = f"Обучение {trained_count}/{target}"

    m7.metric("Модель", model_text)
    m8.metric("Текущее окно", pretty(stats["live_packets"]) + " пак.")
    m9.metric("Потеряно пакетов", pretty(stats["dropped"]))

    if data.get("ml_note") and data.get("replay_finished"):
        st.caption("🧠 Isolation Forest: " + data["ml_note"] + ".")
    elif is_file:
        pass
    elif running and stats["baseline_loaded"]:
        st.caption(
            "🧠 Модель загружена из прошлых сессий — "
            "обучаться заново не нужно, анализ идёт сразу."
        )
    elif running and not stats["trained"]:
        minutes = max(1, target * WINDOW_SECONDS // 60)
        st.progress(
            trained_count / target,
            text=(
                "Isolation Forest изучает твой обычный трафик "
                f"(~{minutes} мин, только в первый раз). "
                "Пакеты считаются и правила работают уже сейчас."
            ),
        )

    # ---------- Диагностика: почему 0 пакетов ----------
    replay = data.get("source") in ("demo", "file")

    no_traffic = (
        running
        and not replay
        and elapsed >= 8
        and stats["raw_lines"] == 0
    )

    if stats["error"]:
        st.error(str(stats["error"]))
    elif no_traffic and data.get("source") == "pktmon":
        st.warning(
            f"📭 За {elapsed} с pktmon не записал ни одного пакета. "
            "Проверь, что интернет работает, и что программа запущена "
            "от имени администратора."
        )
    elif no_traffic:
        st.warning(
            f"📭 За {elapsed} с на интерфейсе {data.get('interface')} "
            "не появилось ни одного пакета. Скорее всего, выбран "
            "не тот интерфейс. Открой ⚙️ Настройки → 📡 Захват "
            "трафика → «⚡ Найти активный интерфейс» — программа "
            "сама выберет нужный."
        )

        if st.button(
            "⚙️ Открыть настройки захвата",
            key="btn_monitor_settings",
            on_click=go_to,
            args=(PAGES[4],),
        ):
            st.rerun()

    elif (
        running
        and stats["bad_lines"] > 0
        and stats["packets"] + stats["live_packets"] == 0
    ):
        st.error(
            "TShark присылает данные, но программа не может их "
            "разобрать. Пришли мне этот пример строки:"
        )
        st.code(stats["last_bad_line"] or "(пусто)")
    elif running and replay:
        st.success(
            f"🎬 Проигрывается запись: {data.get('source_label')} "
            f"({int(float(data.get('replay_progress') or 0) * 100)}%)"
        )
    elif running:
        st.success("🟢 Захват трафика активен")
    elif data.get("replay_finished"):
        st.success(
            f"✅ Запись «{data.get('source_label')}» проанализирована. "
            "Все найденные угрозы — в 🚨 Центре угроз."
        )
    else:
        st.info(
            "Мониторинг остановлен. В боковой панели выбери источник "
            "(📡 Мой ПК, 🎬 Демо или 📂 Файл) и нажми ▶ Старт."
        )

    if stats["save_error"]:
        st.warning(
            "Не удалось сохранить данные: "
            + str(stats["save_error"])
        )

    st.caption(
        "Скорость и счётчики обновляются каждую секунду. Каждые "
        f"{WINDOW_SECONDS} секунд завершённый интервал проверяют "
        "правила обнаружения и Isolation Forest."
    )

    st.divider()

    # ---------- Живой график по секундам ----------
    st.subheader(f"⚡ Живой трафик — каждую секунду (последние {RATE_MINUTES} мин)")

    rate_df = history_frame(rates, RATE_MINUTES)

    if not rate_df.empty and "Пакеты/с" in rate_df.columns:
        rate_df["Пакеты/с"] = pd.to_numeric(
            rate_df["Пакеты/с"], errors="coerce"
        ).fillna(0)

        st.area_chart(
            rate_df.set_index("Метка")[["Пакеты/с"]],
            height=230,
        )
    elif running:
        st.info("Собираю первые секунды трафика...")
    else:
        st.info("Запусти мониторинг, чтобы увидеть живой трафик.")

    render_talkers(data, running)

    st.subheader(
        f"📈 Графики по интервалам {WINDOW_SECONDS} с "
        f"(последние {INTERVAL_MINUTES} мин)"
    )

    rows = list(history)

    if stats["running"]:
        rows.append({
            "Метка": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Пакеты": stats["live_packets"],
            "Байты": stats["live_bytes"],
            "SYN": stats["live_syn"],
            "Статус": "ТЕКУЩИЙ",
        })

    df = history_frame(rows, INTERVAL_MINUTES)

    if df.empty:
        st.info("Запусти мониторинг, чтобы увидеть графики.")
    else:
        chart = df.set_index("Метка")

        left, right = st.columns(2)

        with left:
            st.markdown("**Сетевые пакеты**")
            st.line_chart(chart[["Пакеты"]], height=270)

        with right:
            st.markdown("**Объём трафика (байты)**")
            st.area_chart(chart[["Байты"]], height=270)

        st.markdown("**TCP SYN и RST**")
        columns = [c for c in ("SYN", "RST") if c in chart.columns]
        st.line_chart(chart[columns], height=220)

    if history:
        st.subheader("📋 История интервалов")

        table = pd.DataFrame(history[-300:]).iloc[::-1]

        if "Статус" in table.columns:
            table["Статус"] = table["Статус"].map(
                lambda s: STATUS_LABEL.get(s, s)
            )

        columns = [c for c in TABLE_COLUMNS if c in table.columns]

        st.dataframe(
            table[columns],
            width="stretch",
            hide_index=True,
            height=380,
        )


def page_monitor():
    live_monitor()


# ============================================================
# PAGE: ЦЕНТР УГРОЗ
# ============================================================

def render_threat_card(item):
    level = item.get("Уровень", "")
    icon = SEVERITY_ICON.get(level, "🚨")
    title = SEVERITY_TITLE.get(level, "Подозрительная активность")

    with st.container(border=True):
        st.markdown(f"### {icon} {title}")

        st.caption(
            f"Время: {item.get('Метка') or item.get('Время', '—')} • "
            f"Уровень: {level or '—'} • "
            f"AI Score: {fmt_score(item.get('AI Score'))}"
        )

        reasons = [
            r for r in str(item.get("Причины") or "").split(" | ")
            if r.strip()
        ]

        if reasons:
            st.markdown("\n".join(f"- {r}" for r in reasons))
        else:
            st.caption("Модель отметила интервал как необычный.")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Пакеты", pretty(item.get("Пакеты")))
        c2.metric("Трафик", pretty_bytes(item.get("Байты")))
        c3.metric("SYN", pretty(item.get("SYN")))
        c4.metric("Порты", pretty(item.get("Порты")))

        talkers = item.get("Источники трафика") or []

        if talkers:
            st.markdown("**🌐 Откуда был трафик в этот момент:**")
            st.dataframe(
                talkers_frame(talkers),
                width="stretch",
                hide_index=True,
            )

            top_ip = talkers[0].get("Адрес")

            if top_ip:
                st.caption(
                    "Проверить в Wireshark: фильтр "
                    f"`ip.addr == {top_ip}`" if ":" not in top_ip
                    else f"Проверить в Wireshark: фильтр `ipv6.addr == {top_ip}`"
                )


def render_threats(history, level):
    anomalies = anomalies_of(history)
    high = sum(1 for x in anomalies if x.get("Уровень") == "ВЫСОКИЙ")

    a, b, c, d = st.columns(4)
    a.metric("Интервалы", len(history))
    b.metric("Аномалии", len(anomalies))

    percentage = len(anomalies) / len(history) * 100 if history else 0
    c.metric("Доля аномалий", f"{percentage:.1f}%")
    d.metric("🔴 Высокий уровень", high)

    st.divider()

    selected = [
        x for x in anomalies
        if level is None or x.get("Уровень") == level
    ]

    if not anomalies:
        st.success("Аномалий пока нет.")
    elif not selected:
        st.info("Нет аномалий выбранного уровня.")
    else:
        shown = selected[-20:]
        st.warning(
            f"Показано аномальных интервалов: {len(shown)} "
            f"из {len(selected)}"
        )

        for item in reversed(shown):
            render_threat_card(item)

    st.info(
        "Аномалия — отклонение от обычной сетевой активности, "
        "а не доказанная атака."
    )


@st.fragment(run_every="1s")
def live_threats(level):
    if not current_user():
        return

    render_threats(history_of(snapshot()), level)


def page_threats(user):
    st.subheader("🚨 Центр угроз")

    left, right = st.columns(2)

    with left:
        st.segmented_control(
            "Данные",
            options=THREAT_SOURCES,
            key="threat_source",
            selection_mode="single",
        )

    with right:
        st.segmented_control(
            "Уровень угрозы",
            options=list(THREAT_FILTERS),
            key="threat_filter",
            selection_mode="single",
        )

    level = THREAT_FILTERS.get(ss.threat_filter or "Все")

    if (ss.threat_source or THREAT_SOURCES[0]) == THREAT_SOURCES[0]:
        live_threats(level)
    else:
        render_threats(
            database.load_intervals(user["id"], hours=24),
            level,
        )

    with st.expander("🔎 Как проверить подозрительную активность в Wireshark"):
        st.markdown(
            "1. Запомни **время** аномалии из карточки.\n"
            "2. Открой Wireshark на том же интерфейсе и примени фильтр:\n"
            "   - `tcp.flags.syn == 1 && tcp.flags.ack == 0` — попытки соединений\n"
            "   - `tcp.flags.reset == 1` — сброшенные соединения\n"
            "   - `arp.duplicate-address-detected` — конфликт IP/MAC\n"
            "   - `dns` — DNS-запросы\n"
            "   - `icmp || icmpv6` — ping и ICMP\n"
            "   - `ip.addr == 192.168.1.10` — всё по конкретному адресу\n"
            "3. Меню **Statistics → Conversations** покажет, кто с кем "
            "общался больше всего.\n"
            "4. Если источник — твой компьютер, выполни `netstat -ano` "
            "в командной строке и найди программу по PID в Диспетчере задач."
        )


# ============================================================
# PAGE: ОТЧЁТЫ
# ============================================================

def page_reports(user):
    st.subheader("📄 Отчёты CyberAI Lab")

    st.markdown(
        "Подробный отчёт с графиком трафика, основными показателями, "
        "выводами, уровнями угроз и причинами аномалий."
    )

    st.segmented_control(
        "Источник данных",
        options=REPORT_SOURCES,
        key="report_source",
        selection_mode="single",
        width="stretch",
    )

    source = ss.report_source or REPORT_SOURCES[0]

    if source == REPORT_SOURCES[0]:
        data = snapshot()
        history = history_of(data)
        running = bool(data.get("running"))
    elif source == REPORT_SOURCES[1]:
        history = database.load_intervals(user["id"], hours=24)
        running = False
    else:
        history = database.load_intervals(user["id"])
        running = False

    stats = get_stats({"history": history, "running": running})

    a, b, c, d = st.columns(4)
    a.metric("Интервалы", stats["intervals"])
    b.metric("Пакеты", pretty(stats["packets"]))
    c.metric("Аномалии", stats["anomalies"])
    d.metric("🔴 Высокий", stats["high"])

    st.divider()

    if not history:
        st.info("Для этого источника пока нет данных. Запусти мониторинг.")

    if st.button(
        "🧾 Сформировать PDF-отчёт",
        type="primary",
        width="stretch",
    ):
        with st.spinner("Создаю PDF..."):
            try:
                ss.pdf_bytes = create_pdf(history, {
                    "username": user["username"],
                    "source": source,
                    "running": running,
                })
                ss.pdf_source = source
                ss.pdf_time = datetime.now().strftime("%Y%m%d_%H%M")
            except Exception as exc:
                ss.pdf_bytes = None
                st.error("Ошибка создания PDF: " + str(exc))

    if ss.get("pdf_bytes") and ss.get("pdf_source") == source:
        st.download_button(
            "📥 Скачать PDF-отчёт",
            data=ss.pdf_bytes,
            file_name=(
                f"CyberAI_Report_{user['username']}_{ss.pdf_time}.pdf"
            ),
            mime="application/pdf",
            width="stretch",
        )

    if history:
        csv = pd.DataFrame(history).to_csv(index=False).encode("utf-8-sig")

        st.download_button(
            "📊 Скачать CSV",
            data=csv,
            file_name=f"CyberAI_History_{user['username']}.csv",
            mime="text/csv",
            width="stretch",
        )

    st.caption("PDF формируется по кнопке, чтобы страница не тормозила.")

    st.divider()
    st.subheader("🗂️ Моё хранилище")

    summary = database.history_summary(user["id"])

    s1, s2, s3 = st.columns(3)
    s1.metric("Сохранено интервалов", pretty(summary["total"]))
    s2.metric("Из них аномалий", pretty(summary["anomalies"]))
    s3.metric("Сессий мониторинга", summary["sessions"])

    with st.expander("🗑️ Очистить сохранённую историю"):
        confirm = st.checkbox(
            "Я понимаю, что моя история удалится безвозвратно"
        )

        if st.button("Удалить мою историю", disabled=not confirm):
            database.clear_history(user["id"])
            ss.pdf_bytes = None
            st.success("История удалена.")


# ============================================================
# PAGE: AI ASSISTANT
# ============================================================

def page_ai(user):
    left, right = st.columns([4, 1])

    with left:
        st.subheader("🤖 CyberAI Assistant")
        if ai_mode() == "own":
            st.caption(f"Модель {GROQ_MODEL} через Groq • твой ключ")
        elif ai_mode() in ("server", "proxy"):
            st.caption(
                f"Модель {GROQ_MODEL} через Groq • общий ключ "
                f"(до {SHARED_AI_LIMIT} сообщений за 10 мин)"
            )
        else:
            st.caption(f"Модель {GROQ_MODEL} через Groq")

    with right:
        if st.button("🗑️ Очистить", width="stretch"):
            ss.chat_history = []
            st.rerun()

    flash = ss.pop("groq_flash", None)
    if flash:
        st.success(flash)

    if not ai_available():
        st.info(
            "Чтобы начать беседу, подключи бесплатный ключ Groq — "
            "это займёт 1–2 минуты."
        )

        with st.container(border=True):
            render_groq_setup("ai", user)

        return

    if ss.get("answer_style") not in ANSWER_STYLES:
        ss.answer_style = ANSWER_STYLES[0]

    st.segmented_control(
        "Стиль ответов",
        options=ANSWER_STYLES,
        key="answer_style",
        selection_mode="single",
    )

    q1, q2, q3 = st.columns(3)
    quick = None
    force_network = False

    if q1.button("📊 Проанализируй мою сеть", width="stretch"):
        quick = (
            "Проанализируй текущую статистику моей сети: "
            "что выглядит нормально, а что подозрительно?"
        )
        force_network = True

    if q2.button("🚨 Объясни аномалии", width="stretch"):
        quick = (
            "Объясни последние обнаруженные аномалии простыми словами "
            "и подскажи, как их проверить в Wireshark."
        )
        force_network = True

    if q3.button("🛡️ Как защитить сеть?", width="stretch"):
        quick = (
            "Дай короткий чек-лист, как защитить мою домашнюю сеть "
            "и компьютер."
        )

    if not ss.chat_history and not quick:
        st.info(
            f"Привет, {user['username']}! Я CyberAI. Спроси меня о "
            "кибербезопасности или попроси проанализировать "
            "текущую статистику сети."
        )

    for message in ss.chat_history:
        with st.chat_message(message["role"]):
            st.markdown(clean_answer(message["content"]))

    typed = st.chat_input("Напиши сообщение CyberAI...")
    question = typed or quick

    if typed:
        force_network = False

    if not question:
        return

    # Общий ключ сервера: ограничиваем, чтобы один человек
    # не израсходовал весь лимит Groq.
    if ai_mode() in ("server", "proxy"):
        limit_key = f"ai:{user['id']}"

        if len(recent_events(limit_key)) >= SHARED_AI_LIMIT:
            st.warning(
                f"⏳ На общем ключе можно отправить {SHARED_AI_LIMIT} "
                "сообщений за 10 минут. Подожди немного или подключи "
                "свой бесплатный ключ в ⚙️ Настройках — тогда "
                "ограничения не будет."
            )
            return

        add_event(limit_key)

    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        is_error = False

        try:
            # Ответ показывается целиком, когда готов, — страница
            # не дёргается вниз, пока ты читаешь.
            with st.spinner("CyberAI думает..."):
                answer = ask_ai(question, snapshot(), force_network)

            if not answer:
                answer = "AI не вернул ответ. Попробуй переформулировать."
                is_error = True

        except Exception as exc:
            answer = "⚠️ Ошибка AI:\n\n" + explain_ai_error(exc)
            is_error = True

        st.markdown(answer)

    scroll_to_last_answer()

    ss.chat_history.extend([
        {"role": "user", "content": question, "error": is_error},
        {"role": "assistant", "content": answer, "error": is_error},
    ])



# ============================================================
# НАСТРОЙКИ ЗАХВАТА
# ============================================================

PREFERRED_NAMES = ("wi-fi", "wifi", "беспровод", "wireless", "ethernet")


def save_interface(user_id, path, number):
    old = database.get_settings(user_id)["interface"]

    database.save_settings(
        user_id,
        tshark_path=path,
        interface=str(number),
    )

    # Другой интерфейс = другая сеть: старая «норма» не подходит.
    if old and old != str(number):
        database.clear_baseline(user_id)


def default_interface_index(interfaces, saved, probe):
    numbers = [i["number"] for i in interfaces]

    if saved in numbers:
        return numbers.index(saved)

    if probe:
        candidates = [
            i for i in interfaces
            if not is_loopback(i)
            and probe.get(i["number"], {}).get("packets", 0) > 0
        ]

        if candidates:
            best = max(
                candidates,
                key=lambda i: probe[i["number"]]["packets"],
            )
            return numbers.index(best["number"])

    for n, item in enumerate(interfaces):
        if any(word in item["name"].lower() for word in PREFERRED_NAMES):
            return n

    return 0


def render_capture_settings(user, settings):
    running = bool(snapshot().get("running"))

    if running:
        st.warning("Останови мониторинг, чтобы изменить настройки захвата.")

    path = st.text_input(
        "Путь к tshark.exe",
        value=settings["tshark_path"] or find_tshark(),
        key="tshark_path_input",
        disabled=running,
        help="Обычно C:\\Program Files\\Wireshark\\tshark.exe",
    )
    path = path.strip().strip('"')

    left, right = st.columns(2)

    show = left.button(
        "🔍 Показать интерфейсы",
        disabled=running,
        width="stretch",
    )

    auto = right.button(
        "⚡ Найти активный интерфейс",
        type="primary",
        disabled=running,
        width="stretch",
        help=(
            "Программа 3 секунды слушает все сетевые карты сразу "
            "и выбирает ту, где больше всего трафика."
        ),
    )

    if show or auto:
        try:
            ss.interfaces = [
                i for i in list_interfaces(path) if is_capture_device(i)
            ]
            ss.probe = {}
        except Exception as exc:
            ss.interfaces = []
            st.error(str(exc))

    interfaces = ss.get("interfaces") or []

    if auto and interfaces:
        with st.spinner("Слушаю все интерфейсы 3 секунды..."):
            ss.probe = probe_interfaces(
                path, [i["number"] for i in interfaces], seconds=3
            )

        candidates = [
            i for i in interfaces
            if not is_loopback(i)
            and ss.probe.get(i["number"], {}).get("packets", 0) > 0
        ]

        if candidates:
            best = max(
                candidates,
                key=lambda i: ss.probe[i["number"]]["packets"],
            )
            count = ss.probe[best["number"]]["packets"]

            save_interface(user["id"], path, best["number"])
            settings = database.get_settings(user["id"])

            st.success(
                f"✅ Выбран интерфейс {best['number']} — {best['name']} "
                f"({count} пакетов за 3 с). Сохранено! "
                "Теперь нажми ▶ Старт в боковой панели."
            )
        else:
            st.warning(
                "Ни на одном интерфейсе не нашлось трафика за 3 секунды. "
                "Открой любой сайт или видео и нажми кнопку ещё раз. "
                "Если не помогает — переустанови Npcap с галочкой "
                "«Install Npcap in WinPcap API-compatible Mode»."
            )

    probe = ss.get("probe") or {}

    if interfaces:
        def label(item):
            text = f"{item['number']} — {item['name']}"
            result = probe.get(item["number"])

            if result is not None:
                text += f"  •  {pretty(result['packets'])} пак. за 3 с"

            if is_loopback(item):
                text += "  (локальный, не сеть)"

            return text

        labels = [label(i) for i in interfaces]

        choice = st.selectbox(
            "Сетевой интерфейс",
            labels,
            index=default_interface_index(
                interfaces, settings["interface"], probe
            ),
            disabled=running,
        )

        st.caption(
            "Обычно нужен «Wi-Fi» или «Ethernet» — тот, где "
            "больше всего пакетов."
        )

        if st.button("💾 Сохранить выбранный", disabled=running):
            number = interfaces[labels.index(choice)]["number"]
            save_interface(user["id"], path, number)
            st.success(f"Сохранено: {choice}")
    else:
        st.info(
            "Нажми «⚡ Найти активный интерфейс» — программа сама "
            "выберет сеть, через которую идёт трафик."
        )

    with st.expander("Ввести номер интерфейса вручную"):
        manual = st.text_input(
            "Номер интерфейса (из команды tshark -D)",
            value=settings["interface"],
            disabled=running,
        )

        if st.button("Сохранить номер", disabled=running):
            save_interface(user["id"], path, manual.strip())
            st.success("Сохранено.")

    current = database.get_settings(user["id"])
    st.caption(
        f"Сейчас сохранено: путь «{current['tshark_path'] or 'авто'}», "
        f"интерфейс «{current['interface'] or 'не выбран'}»."
    )

    st.divider()
    st.markdown("#### 🧠 Обученная модель")

    info = database.baseline_info(user["id"])

    if info:
        st.caption(
            f"Сохранена «норма» из {info['windows']} интервалов "
            f"(обновлена {info['updated_at']}). При старте модель "
            "загружается сразу — без 2 минут обучения."
        )

        if st.button("🔄 Сбросить и обучить заново", disabled=running):
            database.clear_baseline(user["id"])
            st.success("Готово. При следующем ▶ Старт модель обучится заново.")
    else:
        st.caption(
            "Модель ещё не обучена. После первого запуска (~2 мин) "
            "она сохранится и в следующий раз загрузится мгновенно."
        )


# ============================================================
# НАСТРОЙКИ ПОЧТЫ
# ============================================================

def render_email_settings(user):
    st.markdown("#### 📧 Почта аккаунта")

    if mailer.is_demo():
        st.info(
            "🧪 Сейчас **демо-режим почты**: коды не отправляются в "
            "письмах, а печатаются в терминале, где запущен streamlit. "
            "Для учебного проекта этого достаточно."
        )

        with st.expander("📖 Как включить настоящие письма (Gmail)"):
            st.markdown(
                "1. Заведи или возьми Gmail, с которого программа будет "
                "отправлять коды (лучше отдельный, например "
                "`cyberai.lab.codes@gmail.com`).\n"
                "2. Включи в нём **двухэтапную аутентификацию**: "
                "Google-аккаунт → Безопасность.\n"
                "3. Открой **myaccount.google.com/apppasswords**, введи "
                "название `CyberAI Lab` и нажми **Создать**. Google покажет "
                "пароль из 16 букв — скопируй его.\n"
                "4. Открой в папке проекта файл **.streamlit/secrets.toml** "
                "(он уже создан) и заполни:\n"
                "```toml\n"
                "[email]\n"
                'smtp_server = "smtp.gmail.com"\n'
                "smtp_port = 465\n"
                'user = "cyberai.lab.codes@gmail.com"\n'
                'password = "abcd efgh ijkl mnop"\n'
                'sender_name = "CyberAI Lab"\n'
                "```\n"
                "5. Сохрани файл и обнови страницу.\n\n"
                "Для Mail.ru: `smtp.mail.ru`, для Яндекса: `smtp.yandex.ru` "
                "(порт тоже 465, тоже нужен пароль приложения)."
            )

            st.link_button(
                "🌐 Открыть страницу паролей приложений Google",
                "https://myaccount.google.com/apppasswords",
            )

    if not user.get("email"):
        st.warning(
            "К аккаунту не привязана почта — если забудешь пароль, "
            "восстановить его будет нельзя. Привяжи почту ниже."
        )

    key = client_key()
    pending = ss.get("email_change")

    if pending:
        st.markdown(
            f"📨 Код отправлен на **{database.mask_email(pending)}**."
        )
        demo_hint("change")

        with st.form("email_change_code_form"):
            code = st.text_input(
                "Код из письма",
                max_chars=database.CODE_LENGTH,
            )
            confirm = st.form_submit_button("✅ Подтвердить почту")

        if confirm:
            ok, error = database.verify_email_code(pending, "change", code)

            if not ok:
                st.error(error)
            else:
                ok, message = database.set_user_email(user["id"], pending)

                if ok:
                    ss.user["email"] = pending
                    ss.pop("email_change", None)
                    ss.email_flash = message
                    st.rerun()
                else:
                    st.error(message)

        if st.button("Отмена", key="email_change_cancel"):
            ss.pop("email_change", None)
            st.rerun()

        return

    flash = ss.pop("email_flash", None)
    if flash:
        st.success(flash)

    with st.form("email_change_form", clear_on_submit=True):
        value = st.text_input(
            "Новая почта" if user.get("email") else "Почта",
            placeholder="name@gmail.com",
        )
        send = st.form_submit_button(
            "📨 Отправить код подтверждения"
        )

    if send:
        value = database.normalize_email(value)
        error = database.validate_email(value)

        if not error and value == database.normalize_email(user.get("email")):
            error = "Эта почта уже привязана к твоему аккаунту."

        if not error and database.email_exists(value):
            error = "Эта почта уже привязана к другому аккаунту."

        if not error:
            error = send_code_to(value, "change", key)

        if error:
            st.error(error)
        else:
            ss.email_change = value
            st.rerun()


# ============================================================
# PAGE: НАСТРОЙКИ
# ============================================================

def page_settings(user):
    st.subheader("⚙️ Настройки")

    flash = ss.pop("groq_flash", None)
    if flash:
        st.success(flash)

    tab_ai, tab_capture, tab_account = st.tabs(
        ["🤖 Groq AI", "📡 Захват трафика", "👤 Аккаунт"]
    )

    settings = database.get_settings(user["id"])

    # ---------------- Groq ----------------
    with tab_ai:
        key = ss.get("groq_key") or ""

        if key:
            st.success(f"Ключ подключён: `{key[:4]}…{key[-4:]}`")

            if settings["groq_key"]:
                st.caption("Ключ сохранён в аккаунте в зашифрованном виде.")
            else:
                st.caption("Ключ действует только до выхода из аккаунта.")

            if st.button("❌ Удалить ключ"):
                ss.groq_key = ""
                database.save_settings(user["id"], groq_key="")
                st.rerun()

            with st.expander("🔁 Заменить ключ"):
                render_groq_setup("replace", user)
        else:
            render_groq_setup("settings", user)

    # ---------------- Захват ----------------
    with tab_capture:
        render_capture_settings(user, settings)

    # ---------------- Аккаунт ----------------
    with tab_account:
        st.markdown(f"**Логин:** {user['username']}")
        st.markdown(f"**Почта:** {user.get('email') or 'не привязана'}")
        st.markdown(f"**Аккаунт создан:** {user.get('created_at') or '—'}")
        st.markdown(f"**Предыдущий вход:** {user.get('last_login') or 'первый вход'}")

        st.divider()
        render_email_settings(user)

        st.divider()
        st.markdown("#### 🔒 Смена пароля")

        with st.form("change_password_form", clear_on_submit=True):
            old = st.text_input("Текущий пароль", type="password")
            new = st.text_input("Новый пароль", type="password")
            new2 = st.text_input("Повтори новый пароль", type="password")
            submitted = st.form_submit_button("Изменить пароль")

        if submitted:
            ok, message = database.change_password(
                user["id"], old, new, new2
            )

            if ok:
                # Новый пароль — выкидываем все остальные устройства.
                database.delete_user_sessions(
                    user["id"], keep_token=ss.get("session_token")
                )
                st.success(message + " Другие устройства вышли из аккаунта.")
            else:
                st.error(message)

        st.divider()
        st.markdown("#### 💻 Устройства")

        sessions = database.count_sessions(user["id"])
        st.caption(
            f"Запомненных входов (браузеров): {sessions}. "
            "Если входил с чужого компьютера — нажми кнопку ниже."
        )

        if st.button("🚪 Выйти на всех других устройствах"):
            database.delete_user_sessions(
                user["id"], keep_token=ss.get("session_token")
            )
            st.success("Готово: на других устройствах нужно войти заново.")


# ============================================================
# MAIN
# ============================================================

init_storage()
try_restore_session()

if not current_user():
    if ss.pop("clear_cookie_pending", False):
        set_browser_cookie("", 0)

    render_auth()
    st.stop()

pending = ss.pop("pending_cookie", None)

if pending:
    set_browser_cookie(pending, database.SESSION_DAYS * 24 * 3600)

init_session()
inject_ui_helpers()

user = current_user()
render_sidebar(user)

st.title("🛡️ CyberAI Lab")
st.caption(
    "Интеллектуальная система мониторинга и обнаружения аномалий "
    f"сетевого трафика • аккаунт: {user['username']}"
)

st.segmented_control(
    "Навигация",
    options=PAGES,
    key="page",
    on_change=on_nav_change,
    selection_mode="single",
    label_visibility="collapsed",
    width="stretch",
)

page = ss.page or ss.last_page

st.divider()

if page == PAGES[0]:
    page_monitor()
elif page == PAGES[1]:
    page_threats(user)
elif page == PAGES[2]:
    page_reports(user)
elif page == PAGES[3]:
    page_ai(user)
elif page == PAGES[4]:
    page_settings(user)
