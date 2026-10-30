"""
CyberAI Lab — отправка писем с кодами подтверждения.

Два режима:
- ДЕМО (по умолчанию): письма не отправляются, код печатается
  в терминале, где запущен streamlit. Ничего настраивать не нужно.
- НАСТОЯЩАЯ ПОЧТА: если заполнен .streamlit/secrets.toml:

    [email]
    smtp_server = "smtp.gmail.com"
    smtp_port = 465
    user = "твоя.почта@gmail.com"
    password = "abcd efgh ijkl mnop"   # пароль приложения, НЕ обычный
    sender_name = "CyberAI Lab"
"""

import smtplib
import ssl
import sys
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr

import streamlit as st


PURPOSE_TEXT = {
    "register": (
        "Подтверждение регистрации",
        "Ты регистрируешься в CyberAI Lab. Введи этот код, "
        "чтобы подтвердить почту:",
    ),
    "reset": (
        "Восстановление пароля",
        "Кто-то (надеемся, ты) запросил сброс пароля в CyberAI Lab. "
        "Введи этот код, чтобы задать новый пароль:",
    ),
    "change": (
        "Привязка почты",
        "Ты привязываешь эту почту к аккаунту CyberAI Lab. "
        "Введи этот код:",
    ),
}


def mail_settings():
    try:
        section = st.secrets.get("email")
    except Exception:
        return None

    if not section:
        return None

    settings = dict(section)
    required = ("smtp_server", "user", "password")

    if not all(str(settings.get(key) or "").strip() for key in required):
        return None

    return settings


# Текст ошибки, если последнее письмо не ушло и код
# был напечатан в терминале вместо отправки.
LAST_FALLBACK = None


def is_demo():
    """True — почта не настроена, коды печатаются в терминале."""
    return mail_settings() is None


def mail_configured():
    # В демо-режиме коды тоже «отправляются» — в терминал.
    return True


def _print_code(to_email, code, purpose):
    title, _ = PURPOSE_TEXT.get(purpose, PURPOSE_TEXT["register"])
    now = datetime.now().strftime("%H:%M:%S")

    lines = [
        "",
        "╔══════════════════════════════════════════════╗",
        "║  📨 CyberAI Lab — ДЕМО-ПОЧТА                 ║",
        "╚══════════════════════════════════════════════╝",
        f"  Время:  {now}",
        f"  Кому:   {to_email}",
        f"  Тема:   {title}",
        f"  КОД:    {code}",
        "  (действует 10 минут)",
        "",
    ]

    text = "\n".join(lines)

    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        # Старые консоли Windows не умеют рамки и эмодзи.
        sys.stdout.write(
            f"\n[CyberAI DEMO MAIL] {now} to={to_email} "
            f"code={code}\n"
        )
        sys.stdout.flush()


def _html(code, title, text):
    digits = "".join(
        f'<span style="display:inline-block;width:42px;height:52px;'
        f'line-height:52px;margin:0 4px;border-radius:10px;'
        f'background:#162239;border:1px solid #2c3c57;color:#e5eaf5;'
        f'font-size:28px;font-weight:bold;font-family:monospace;">{d}</span>'
        for d in code
    )

    return f"""
    <div style="background:#0a1020;padding:32px 0;font-family:Segoe UI,Arial,sans-serif;">
      <div style="max-width:480px;margin:0 auto;background:#10192b;
                  border:1px solid #29344c;border-radius:16px;padding:32px;">
        <div style="font-size:22px;font-weight:bold;color:#e5eaf5;">🛡️ CyberAI Lab</div>
        <div style="color:#93c5fd;margin-top:4px;">{title}</div>
        <p style="color:#c9d3e6;line-height:1.5;margin:24px 0;">{text}</p>
        <div style="text-align:center;margin:24px 0;">{digits}</div>
        <p style="color:#8a97b0;font-size:13px;line-height:1.5;">
          Код действует 10 минут. Никому его не сообщай.<br>
          Если ты ничего не запрашивал — просто проигнорируй это письмо.
        </p>
      </div>
    </div>
    """


def send_code(to_email, code, purpose):
    """Отправляет код. Возвращает None или текст ошибки."""
    settings = mail_settings()

    if settings is None:
        _print_code(to_email, code, purpose)
        return None

    title, text = PURPOSE_TEXT.get(purpose, PURPOSE_TEXT["register"])

    message = EmailMessage()
    message["Subject"] = f"{code} — {title} | CyberAI Lab"
    message["From"] = formataddr((
        str(settings.get("sender_name") or "CyberAI Lab"),
        settings["user"],
    ))
    message["To"] = to_email
    message.set_content(
        f"{title}\n\n{text}\n\n    {code}\n\n"
        "Код действует 10 минут. Если ты ничего не запрашивал — "
        "проигнорируй письмо."
    )
    message.add_alternative(_html(code, title, text), subtype="html")

    server = settings["smtp_server"]
    port = int(settings.get("smtp_port") or 465)
    password = str(settings["password"]).replace(" ", "")
    context = ssl.create_default_context()

    error = None

    try:
        if port == 465:
            with smtplib.SMTP_SSL(server, port, context=context, timeout=20) as smtp:
                smtp.login(settings["user"], password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(server, port, timeout=20) as smtp:
                smtp.starttls(context=context)
                smtp.login(settings["user"], password)
                smtp.send_message(message)

    except smtplib.SMTPAuthenticationError:
        error = (
            "почтовый сервер не принял логин или пароль приложения "
            "(аккаунт мог быть заблокирован или пароль сменился)"
        )
    except smtplib.SMTPRecipientsRefused:
        return "Почтовый сервер отклонил адрес получателя. Проверь почту."
    except (OSError, smtplib.SMTPException) as exc:
        error = str(exc)

    if error:
        # Страховка для показа: письмо не ушло — печатаем код
        # в терминал, чтобы регистрация не сломалась.
        global LAST_FALLBACK
        LAST_FALLBACK = error

        try:
            print(f"\n⚠️ CyberAI Lab: письмо не отправилось — {error}",
                  flush=True)
        except UnicodeEncodeError:
            print(f"\n[CyberAI] mail failed: {error}", flush=True)

        _print_code(to_email, code, purpose)
        return None

    LAST_FALLBACK = None
    return None
