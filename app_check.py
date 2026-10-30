"""
CyberAI Lab — самопроверка собранной программы.

Запускается командой  CyberAI_Lab.exe --check  (так делает GitHub
после сборки): проверяет, что все библиотеки на месте и что движок
находит атаки в демо-трафике.
"""

import os
import tempfile
import time


def run():
    try:
        import cryptography.fernet  # noqa: F401
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot  # noqa: F401
        import numpy  # noqa: F401
        import openai  # noqa: F401
        import pandas  # noqa: F401
        import psutil  # noqa: F401
        import reportlab.platypus  # noqa: F401
        import sklearn.ensemble  # noqa: F401
        import streamlit  # noqa: F401

        if os.name == "nt":
            import webview  # noqa: F401  — окно приложения

        import cyberai_engine
        import database  # noqa: F401
        import demo_traffic
        import mailer  # noqa: F401
        import pcap_reader  # noqa: F401

        path = os.path.join(tempfile.mkdtemp(), "demo.pcap")
        demo_traffic.write_demo_pcap(path)

        engine = cyberai_engine.CyberAIEngine()
        engine.start_replay(path, source="file", speed=0)

        deadline = time.time() + 120
        while engine.snapshot()["running"] and time.time() < deadline:
            time.sleep(0.2)

        snapshot = engine.snapshot()
        anomalies = [
            row for row in snapshot["history"]
            if row["Статус"] == "АНОМАЛИЯ"
        ]

        if snapshot["error"] or len(anomalies) < 4:
            print("CHECK FAILED:", snapshot["error"] or len(anomalies))
            return 1

        print(
            f"CHECK OK: streamlit {streamlit.__version__}, "
            f"{len(snapshot['history'])} windows, {len(anomalies)} anomalies"
        )
        return 0

    except Exception as exc:
        print("CHECK FAILED:", repr(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
