"""
CyberAI Lab — запуск как обычной программы (CyberAI_Lab.exe).

Поднимает интерфейс на этом компьютере (только для него самого,
адрес 127.0.0.1) и открывает его в браузере.

    CyberAI_Lab.exe            — обычный запуск
    CyberAI_Lab.exe --check    — самопроверка сборки (для GitHub)
"""

import os
import socket
import sys


def _bundled_imports():
    # PyInstaller не видит импорты внутри app.py (его запускает Streamlit),
    # поэтому перечисляем здесь всё, что нужно положить в .exe.
    # Сама функция никогда не вызывается.
    import app_check  # noqa: F401
    import cryptography.fernet  # noqa: F401
    import cyberai_engine  # noqa: F401
    import database  # noqa: F401
    import demo_traffic  # noqa: F401
    import mailer  # noqa: F401
    import matplotlib.pyplot  # noqa: F401
    import numpy  # noqa: F401
    import openai  # noqa: F401
    import pandas  # noqa: F401
    import pcap_reader  # noqa: F401
    import psutil  # noqa: F401
    import reportlab.platypus  # noqa: F401
    import sklearn.ensemble  # noqa: F401
    import streamlit.components.v1  # noqa: F401


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


def banner(port):
    lines = [
        "",
        "  ==============================================",
        "    CyberAI Lab — мониторинг сети",
        "  ==============================================",
        f"  Открываю в браузере: http://localhost:{port}",
        "  Не закрывай это окно, пока пользуешься программой.",
        "  Чтобы выйти — просто закрой его.",
        "",
    ]

    for line in lines:
        try:
            print(line, flush=True)
        except UnicodeEncodeError:
            print(line.encode("ascii", "replace").decode(), flush=True)


def main():
    base = base_dir()

    if base not in sys.path:
        sys.path.insert(0, base)

    if "--check" in sys.argv:
        import app_check

        sys.exit(app_check.run())

    port = free_port()
    headless = os.environ.get("CYBERAI_HEADLESS") == "1"

    if not headless:
        banner(port)

    from streamlit.web import cli as stcli

    sys.argv = [
        "streamlit", "run", os.path.join(base, "app.py"),
        "--global.developmentMode=false",
        f"--server.port={port}",
        "--server.address=127.0.0.1",
        f"--server.headless={'true' if headless else 'false'}",
        "--server.fileWatcherType=none",
        "--browser.gatherUsageStats=false",
        "--theme.base=dark",
        "--theme.primaryColor=#3b82f6",
        "--theme.backgroundColor=#0a1020",
        "--theme.secondaryBackgroundColor=#162239",
        "--theme.textColor=#e5eaf5",
        "--client.toolbarMode=minimal",
        "--client.showSidebarNavigation=false",
    ]

    sys.exit(stcli.main())


if __name__ == "__main__":
    main()
