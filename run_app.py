"""
CyberAI Lab — запуск как обычного приложения Windows (CyberAI_Lab.exe).

Открывает собственное окно «CyberAI Lab» (движок Edge WebView2,
встроен в Windows 10/11), внутри — интерфейс программы.
Закрыл окно — программа завершилась и остановила запись трафика.

    CyberAI_Lab.exe            — обычный запуск
    CyberAI_Lab.exe --check    — самопроверка сборки (для GitHub)
"""

import os
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path


APP_TITLE = "CyberAI Lab"


# ------------------------------------------------------------
# Без консоли у программы нет stdout — пишем всё в журнал
# ------------------------------------------------------------

def app_folder():
    root = os.environ.get("LOCALAPPDATA") or str(Path.home())
    folder = Path(root) / "CyberAI Lab"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


if sys.stdout is None or sys.stderr is None:
    _log = open(app_folder() / "cyberai.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log


def _bundled_imports():
    # PyInstaller не видит импорты внутри app.py (его запускает Streamlit),
    # поэтому перечисляем здесь всё, что нужно положить в .exe.
    # Сама функция никогда не вызывается.
    import app_check  # noqa: F401
    import cryptography.fernet  # noqa: F401
    import cyberai_engine  # noqa: F401
    import database  # noqa: F401
    import demo_traffic  # noqa: F401
    import matplotlib.pyplot  # noqa: F401
    import numpy  # noqa: F401
    import openai  # noqa: F401
    import pandas  # noqa: F401
    import pcap_reader  # noqa: F401
    import psutil  # noqa: F401
    import reportlab.platypus  # noqa: F401
    import sklearn.ensemble  # noqa: F401
    import streamlit.components.v1  # noqa: F401
    import webview  # noqa: F401


def base_dir():
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def free_port(start=8501):
    for port in range(start, start + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start


# ------------------------------------------------------------
# Сервер интерфейса (Streamlit) — в фоновом потоке
# ------------------------------------------------------------

def start_server(base, port):
    from streamlit.web import bootstrap

    # Streamlit ставит обработчики Ctrl+C, а это можно делать только
    # в главном потоке. Главный поток занят окном — отключаем.
    bootstrap._set_up_signal_handler = lambda *args, **kwargs: None

    options = {
        "global_developmentMode": False,
        "server_port": port,
        "server_address": "127.0.0.1",
        "server_headless": True,
        "server_fileWatcherType": "none",
        "browser_gatherUsageStats": False,
        "theme_base": "dark",
        "theme_primaryColor": "#3b82f6",
        "theme_backgroundColor": "#0a1020",
        "theme_secondaryBackgroundColor": "#162239",
        "theme_textColor": "#e5eaf5",
        "client_toolbarMode": "minimal",
        "client_showSidebarNavigation": False,
    }

    def serve():
        bootstrap.load_config_options(flag_options=options)
        bootstrap.run(os.path.join(base, "app.py"), False, [], options)

    thread = threading.Thread(target=serve, daemon=True, name="streamlit")
    thread.start()
    return thread


def wait_ready(port, seconds=120):
    url = f"http://127.0.0.1:{port}/_stcore/health"
    deadline = time.time() + seconds

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if b"ok" in response.read():
                    return True
        except Exception:
            pass
        time.sleep(0.4)

    return False


def stop_capture():
    """При закрытии окна обязательно останавливаем запись pktmon."""
    try:
        import cyberai_engine

        path = cyberai_engine.find_pktmon()

        if path:
            import subprocess

            subprocess.run(
                [path, "stop"],
                capture_output=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
    except Exception:
        pass


LOADING_HTML = """
<html><body style="margin:0;background:#0a1020;color:#e5eaf5;
font-family:Segoe UI,Arial,sans-serif;display:flex;align-items:center;
justify-content:center;height:100vh;flex-direction:column">
<div style="font-size:64px">🛡️</div>
<div style="font-size:28px;font-weight:600;margin-top:12px">CyberAI Lab</div>
<div style="color:#8a97b0;margin-top:10px">Запускаю программу…</div>
</body></html>
"""


def main():
    base = base_dir()

    if base not in sys.path:
        sys.path.insert(0, base)

    if "--check" in sys.argv:
        import app_check

        sys.exit(app_check.run())

    port = free_port()
    start_server(base, port)
    url = f"http://127.0.0.1:{port}"

    # Режим для автопроверки на GitHub: только сервер, без окна.
    if os.environ.get("CYBERAI_HEADLESS") == "1":
        while True:
            time.sleep(3600)

    try:
        import webview

        window = webview.create_window(
            APP_TITLE,
            html=LOADING_HTML,
            width=1400,
            height=900,
            min_size=(900, 600),
            background_color="#0a1020",
            text_select=True,
        )

        def navigate_when_ready():
            if wait_ready(port):
                window.load_url(url)
            else:
                window.load_html(
                    LOADING_HTML.replace(
                        "Запускаю программу…",
                        "Не удалось запустить. Подробности в файле "
                        "%LOCALAPPDATA%\\\\CyberAI Lab\\\\cyberai.log",
                    )
                )

        webview.start(navigate_when_ready, gui="edgechromium")

    except Exception as exc:
        # Нет WebView2 или что-то пошло не так — открываем в браузере.
        print("Окно приложения не открылось:", repr(exc))
        import webbrowser

        if wait_ready(port):
            webbrowser.open(url)

        while True:
            time.sleep(3600)

    # Окно закрыто — выходим.
    stop_capture()
    os._exit(0)


if __name__ == "__main__":
    main()
