"""
CyberAI Lab 11.0 — хранилище пользователей.

SQLite-база в папке data/:
- аккаунты (пароли хранятся только в виде хэша PBKDF2);
- личные настройки (Groq-ключ хранится в зашифрованном виде);
- история интервалов мониторинга каждого пользователя.
"""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cyberai.db"
SECRET_PATH = DATA_DIR / "secret.key"

PBKDF2_ITERATIONS = 310_000
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 5

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

_SETTING_COLUMNS = {
    "groq_key": "groq_key_enc",
    "tshark_path": "tshark_path",
    "interface": "interface",
}

_DUMMY_SALT = secrets.token_hex(16)
_fernet = None
_fernet_lock = threading.Lock()


# ============================================================
# ПОДКЛЮЧЕНИЕ
# ============================================================

@contextmanager
def _db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with _db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            );

            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,
                groq_key_enc TEXT,
                tshark_path TEXT,
                interface TEXT
            );

            CREATE TABLE IF NOT EXISTS intervals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                session_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                status TEXT,
                data TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_intervals_user_ts
                ON intervals (user_id, ts);

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS baselines (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # ---- Почта (добавляется и в старые базы) ----
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)")
        }

        if "email" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")

        conn.executescript(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
                ON users (email COLLATE NOCASE)
                WHERE email IS NOT NULL;

            CREATE TABLE IF NOT EXISTS email_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE,
                purpose TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_email_codes
                ON email_codes (email, purpose);
            """
        )


# ============================================================
# ПАРОЛИ
# ============================================================

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ITERATIONS,
    ).hex()


def validate_username(username):
    if USERNAME_RE.match(username):
        return None

    if not 3 <= len(username) <= 32:
        return (
            f"Логин должен быть от 3 до 32 символов "
            f"(сейчас {len(username)})."
        )

    bad = sorted({
        ch for ch in username
        if not re.match(r"[A-Za-z0-9_.-]", ch)
    })

    shown = ", ".join(
        "пробел" if ch == " " else f"«{ch}»" for ch in bad
    )

    hint = ""
    if any("Ѐ" <= ch <= "ӿ" for ch in bad):
        hint = (
            " Похоже, часть букв набрана на русской раскладке "
            "(например, «у» вместо «y») — переключи на English "
            "и набери логин заново."
        )

    return (
        f"Недопустимые символы в логине: {shown}. Можно только "
        f"латинские буквы, цифры и знаки _ . -{hint}"
    )


def validate_password(password, username=""):
    if len(password) < 8:
        return "Пароль должен быть не короче 8 символов."

    if len(password) > 128:
        return "Пароль слишком длинный (максимум 128 символов)."

    has_letter = re.search(r"[A-Za-zА-Яа-яЁё]", password)
    has_digit = re.search(r"\d", password)

    if not has_letter or not has_digit:
        return "Пароль должен содержать и буквы, и цифры."

    if username and username.lower() in password.lower():
        return "Пароль не должен содержать логин."

    return None


# ============================================================
# РЕГИСТРАЦИЯ И ВХОД
# ============================================================

def username_exists(username):
    with _db() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    return row is not None


def register_user(username, password, password2, email=None):
    username = username.strip()
    email = normalize_email(email) or None

    error = validate_username(username)
    if error:
        return False, error

    if email:
        error = validate_email(email)
        if error:
            return False, error

        if email_exists(email):
            return False, "Эта почта уже привязана к другому аккаунту."

    if password != password2:
        return False, "Пароли не совпадают."

    error = validate_password(password, username)
    if error:
        return False, error

    salt = secrets.token_hex(16)

    try:
        with _db() as conn:
            cursor = conn.execute(
                "INSERT INTO users "
                "(username, password_hash, salt, created_at, email) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    username,
                    _hash_password(password, salt),
                    salt,
                    _now(),
                    email,
                ),
            )

            conn.execute(
                "INSERT INTO user_settings (user_id) VALUES (?)",
                (cursor.lastrowid,),
            )

    except sqlite3.IntegrityError:
        return False, "Такой логин или почта уже зарегистрированы."

    return True, "Аккаунт создан! Теперь войди под своим логином."


def create_guest_user():
    """Временный аккаунт для знакомства с программой без регистрации."""
    for _ in range(10):
        username = "guest-" + secrets.token_hex(3)
        password = secrets.token_urlsafe(24)
        ok, _ = register_user(username, password, password)

        if ok:
            user, _ = authenticate(username, password)
            return user

    return None


def authenticate(username, password):
    """Вход по логину или по почте."""
    username = username.strip()
    generic = "Неверный логин или пароль."

    with _db() as conn:
        if "@" in username:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
                (normalize_email(username),),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if row is None:
            # Тратим то же время, чтобы нельзя было
            # угадать существующие логины по скорости ответа.
            _hash_password(password, _DUMMY_SALT)
            return None, generic

        if row["locked_until"]:
            locked = datetime.strptime(
                row["locked_until"], "%Y-%m-%d %H:%M:%S"
            )

            if locked > datetime.now():
                seconds = (locked - datetime.now()).total_seconds()
                minutes = max(1, int(seconds // 60) + 1)

                return None, (
                    "Слишком много неудачных попыток. "
                    f"Попробуй через {minutes} мин."
                )

        actual = _hash_password(password, row["salt"])

        if not hmac.compare_digest(row["password_hash"], actual):
            failed = row["failed_attempts"] + 1
            locked_until = None

            if failed >= MAX_FAILED_ATTEMPTS:
                locked_until = (
                    datetime.now() + timedelta(minutes=LOCK_MINUTES)
                ).strftime("%Y-%m-%d %H:%M:%S")
                failed = 0

            conn.execute(
                "UPDATE users SET failed_attempts = ?, "
                "locked_until = ? WHERE id = ?",
                (failed, locked_until, row["id"]),
            )

            return None, generic

        conn.execute(
            "UPDATE users SET failed_attempts = 0, "
            "locked_until = NULL, last_login = ? WHERE id = ?",
            (_now(), row["id"]),
        )

        user = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "created_at": row["created_at"],
            "last_login": row["last_login"],
        }

    return user, "OK"


def change_password(user_id, old_password, new_password, new_password2):
    with _db() as conn:
        row = conn.execute(
            "SELECT username, password_hash, salt "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

        if row is None:
            return False, "Пользователь не найден."

        if not hmac.compare_digest(
            row["password_hash"],
            _hash_password(old_password, row["salt"]),
        ):
            return False, "Текущий пароль указан неверно."

        if new_password != new_password2:
            return False, "Новые пароли не совпадают."

        error = validate_password(new_password, row["username"])
        if error:
            return False, error

        salt = secrets.token_hex(16)

        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? "
            "WHERE id = ?",
            (_hash_password(new_password, salt), salt, user_id),
        )

    return True, "Пароль изменён."


# ============================================================
# ПОЧТА И КОДЫ ПОДТВЕРЖДЕНИЯ
# ============================================================

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")

CODE_LENGTH = 6
CODE_MINUTES = 10           # код действует 10 минут
CODE_MAX_ATTEMPTS = 5       # попыток ввода на один код
CODE_RESEND_SECONDS = 60    # повторная отправка — не чаще раза в минуту
CODE_MAX_PER_HOUR = 5       # не больше 5 писем на почту в час


def normalize_email(email):
    return (email or "").strip().lower()


def validate_email(email):
    email = normalize_email(email)

    if not email:
        return "Введи почту."

    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Похоже, почта написана с ошибкой (пример: name@gmail.com)."

    return None


def email_exists(email):
    with _db() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE",
            (normalize_email(email),),
        ).fetchone()

    return row is not None


def get_user_by_email(email):
    with _db() as conn:
        row = conn.execute(
            "SELECT id, username, email FROM users "
            "WHERE email = ? COLLATE NOCASE",
            (normalize_email(email),),
        ).fetchone()

    return dict(row) if row else None


def _code_hash(email, purpose, code):
    text = f"{normalize_email(email)}|{purpose}|{code.strip()}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def create_email_code(email, purpose):
    """Создаёт 6-значный код. Возвращает (код, None) или (None, ошибка)."""
    email = normalize_email(email)
    now = datetime.now()

    with _db() as conn:
        conn.execute(
            "DELETE FROM email_codes WHERE created_at < ?",
            ((now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),),
        )

        last = conn.execute(
            "SELECT created_at FROM email_codes "
            "WHERE email = ? AND purpose = ? "
            "ORDER BY id DESC LIMIT 1",
            (email, purpose),
        ).fetchone()

        if last:
            passed = (
                now - datetime.strptime(last["created_at"], "%Y-%m-%d %H:%M:%S")
            ).total_seconds()

            if passed < CODE_RESEND_SECONDS:
                wait = int(CODE_RESEND_SECONDS - passed) + 1
                return None, f"Новый код можно запросить через {wait} с."

        hour_ago = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        sent = conn.execute(
            "SELECT COUNT(*) AS n FROM email_codes "
            "WHERE email = ? AND created_at >= ?",
            (email, hour_ago),
        ).fetchone()["n"]

        if sent >= CODE_MAX_PER_HOUR:
            return None, "Слишком много писем на эту почту. Попробуй через час."

        code = "".join(secrets.choice("0123456789") for _ in range(CODE_LENGTH))

        # Старые коды этой почты больше не действуют.
        conn.execute(
            "UPDATE email_codes SET used = 1 "
            "WHERE email = ? AND purpose = ?",
            (email, purpose),
        )

        conn.execute(
            "INSERT INTO email_codes "
            "(email, purpose, code_hash, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                email,
                purpose,
                _code_hash(email, purpose, code),
                now.strftime("%Y-%m-%d %H:%M:%S"),
                (now + timedelta(minutes=CODE_MINUTES)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
            ),
        )

    return code, None


def verify_email_code(email, purpose, code):
    """Проверяет код. Возвращает (True, None) или (False, ошибка)."""
    email = normalize_email(email)
    code = (code or "").strip().replace(" ", "")

    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM email_codes "
            "WHERE email = ? AND purpose = ? AND used = 0 "
            "ORDER BY id DESC LIMIT 1",
            (email, purpose),
        ).fetchone()

        if row is None:
            return False, "Код не найден. Запроси новый."

        if row["expires_at"] < _now():
            return False, "Срок действия кода истёк. Запроси новый."

        if row["attempts"] >= CODE_MAX_ATTEMPTS:
            return False, "Слишком много неверных попыток. Запроси новый код."

        if not hmac.compare_digest(
            row["code_hash"], _code_hash(email, purpose, code)
        ):
            conn.execute(
                "UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?",
                (row["id"],),
            )
            left = CODE_MAX_ATTEMPTS - row["attempts"] - 1

            if left <= 0:
                return False, "Неверный код. Попытки закончились — запроси новый."

            return False, f"Неверный код. Осталось попыток: {left}."

        conn.execute(
            "UPDATE email_codes SET used = 1 WHERE id = ?",
            (row["id"],),
        )

    return True, None


def reset_password_by_email(email, new_password, new_password2):
    user = get_user_by_email(email)

    if user is None:
        return False, "Аккаунт с такой почтой не найден."

    if new_password != new_password2:
        return False, "Пароли не совпадают."

    error = validate_password(new_password, user["username"])
    if error:
        return False, error

    salt = secrets.token_hex(16)

    with _db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ?, "
            "failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (_hash_password(new_password, salt), salt, user["id"]),
        )

        # Старые «Запомнить меня» больше не действуют.
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?",
            (user["id"],),
        )

    return True, (
        f"Пароль для «{user['username']}» изменён. "
        "Теперь войди с новым паролем."
    )


def set_user_email(user_id, email):
    email = normalize_email(email)

    error = validate_email(email)
    if error:
        return False, error

    try:
        with _db() as conn:
            conn.execute(
                "UPDATE users SET email = ? WHERE id = ?",
                (email, user_id),
            )
    except sqlite3.IntegrityError:
        return False, "Эта почта уже привязана к другому аккаунту."

    return True, "Почта привязана к аккаунту."


def mask_email(email):
    """name@gmail.com -> na**@gmail.com"""
    email = normalize_email(email)

    if "@" not in email:
        return email

    name, domain = email.split("@", 1)
    visible = name[:2] if len(name) > 2 else name[:1]

    return f"{visible}{'*' * max(2, len(name) - len(visible))}@{domain}"


# ============================================================
# «ЗАПОМНИТЬ МЕНЯ» — сессии входа
# ============================================================
# В браузер (cookie) кладётся случайный токен, а в базе
# хранится только его SHA-256 хэш. Даже если кто-то украдёт
# файл базы, войти по хэшу нельзя.

SESSION_DAYS = 30


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id, days=SESSION_DAYS):
    token = secrets.token_urlsafe(32)
    expires = (
        datetime.now() + timedelta(days=days)
    ).strftime("%Y-%m-%d %H:%M:%S")

    with _db() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?",
            (_now(),),
        )

        conn.execute(
            "INSERT INTO sessions "
            "(token_hash, user_id, created_at, expires_at, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (_token_hash(token), user_id, _now(), expires, _now()),
        )

    return token


def get_session_user(token):
    if not token or len(token) > 200:
        return None

    token_hash = _token_hash(token)

    with _db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.email, u.created_at,
                   u.last_login, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        if row is None:
            return None

        if row["expires_at"] < _now():
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (token_hash,),
            )
            return None

        conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
            (_now(), token_hash),
        )

        user = {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "created_at": row["created_at"],
            "last_login": row["last_login"],
        }

    return user


def delete_session(token):
    if not token:
        return

    with _db() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (_token_hash(token),),
        )


def delete_user_sessions(user_id, keep_token=None):
    with _db() as conn:
        if keep_token:
            conn.execute(
                "DELETE FROM sessions "
                "WHERE user_id = ? AND token_hash != ?",
                (user_id, _token_hash(keep_token)),
            )
        else:
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                (user_id,),
            )


def count_sessions(user_id):
    with _db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM sessions "
            "WHERE user_id = ? AND expires_at >= ?",
            (user_id, _now()),
        ).fetchone()

    return row["n"] or 0


# ============================================================
# НАСТРОЙКИ (Groq-ключ шифруется)
# ============================================================

def _get_fernet():
    global _fernet

    with _fernet_lock:
        if _fernet is None:
            DATA_DIR.mkdir(parents=True, exist_ok=True)

            if not SECRET_PATH.exists():
                SECRET_PATH.write_bytes(Fernet.generate_key())

            _fernet = Fernet(SECRET_PATH.read_bytes().strip())

        return _fernet


def get_settings(user_id):
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM user_settings WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row is None:
        return {"groq_key": "", "tshark_path": "", "interface": ""}

    groq_key = ""

    if row["groq_key_enc"]:
        try:
            groq_key = _get_fernet().decrypt(
                row["groq_key_enc"].encode()
            ).decode()
        except (InvalidToken, ValueError):
            groq_key = ""

    return {
        "groq_key": groq_key,
        "tshark_path": row["tshark_path"] or "",
        "interface": row["interface"] or "",
    }


def save_settings(user_id, **values):
    with _db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)",
            (user_id,),
        )

        for name, value in values.items():
            column = _SETTING_COLUMNS.get(name)

            if column is None:
                raise ValueError(f"Неизвестная настройка: {name}")

            value = (value or "").strip()

            if name == "groq_key" and value:
                value = _get_fernet().encrypt(value.encode()).decode()

            conn.execute(
                f"UPDATE user_settings SET {column} = ? "
                "WHERE user_id = ?",
                (value or None, user_id),
            )


# ============================================================
# ИСТОРИЯ МОНИТОРИНГА
# ============================================================

def save_interval(user_id, session_id, record):
    with _db() as conn:
        conn.execute(
            "INSERT INTO intervals "
            "(user_id, session_id, ts, status, data) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                session_id,
                record.get("Метка") or _now(),
                record.get("Статус", ""),
                json.dumps(record, ensure_ascii=False, default=str),
            ),
        )


def load_intervals(user_id, hours=None, limit=20000):
    query = "SELECT data FROM intervals WHERE user_id = ?"
    params = [user_id]

    if hours:
        since = (
            datetime.now() - timedelta(hours=hours)
        ).strftime("%Y-%m-%d %H:%M:%S")

        query += " AND ts >= ?"
        params.append(since)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with _db() as conn:
        rows = conn.execute(query, params).fetchall()

    result = []

    for row in reversed(rows):
        try:
            result.append(json.loads(row["data"]))
        except (ValueError, TypeError):
            pass

    return result


def history_summary(user_id):
    with _db() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'АНОМАЛИЯ'
                    THEN 1 ELSE 0 END) AS anomalies,
                COUNT(DISTINCT session_id) AS sessions
            FROM intervals
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

    return {
        "total": row["total"] or 0,
        "anomalies": row["anomalies"] or 0,
        "sessions": row["sessions"] or 0,
    }


def clear_history(user_id):
    with _db() as conn:
        conn.execute(
            "DELETE FROM intervals WHERE user_id = ?",
            (user_id,),
        )


# ============================================================
# ОБУЧЕННАЯ МОДЕЛЬ (чтобы не обучаться заново при каждом старте)
# ============================================================

def save_baseline(user_id, rows):
    with _db() as conn:
        conn.execute(
            "INSERT INTO baselines (user_id, data, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "data = excluded.data, updated_at = excluded.updated_at",
            (user_id, json.dumps(rows), _now()),
        )


def load_baseline(user_id):
    with _db() as conn:
        row = conn.execute(
            "SELECT data FROM baselines WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row is None:
        return []

    try:
        data = json.loads(row["data"])
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def baseline_info(user_id):
    with _db() as conn:
        row = conn.execute(
            "SELECT data, updated_at FROM baselines WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row is None:
        return None

    try:
        size = len(json.loads(row["data"]))
    except (ValueError, TypeError):
        size = 0

    return {"windows": size, "updated_at": row["updated_at"]}


def clear_baseline(user_id):
    with _db() as conn:
        conn.execute(
            "DELETE FROM baselines WHERE user_id = ?",
            (user_id,),
        )
