"""
CyberAI Lab 11.0 — движок захвата и анализа сетевого трафика.

TShark захватывает пакеты. Движок собирает их в окна
по WINDOW_SECONDS секунд и проверяет каждое окно двумя способами:

1. Правила — ищут типичные признаки атак
   (сканирование портов, SYN-flood, ARP-спуфинг и т.д.).
2. Isolation Forest — ищет окна, необычные для ТВОЕЙ сети.
"""

import ipaddress
import os
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from queue import Empty, Full, Queue

import numpy as np
from sklearn.ensemble import IsolationForest

import pcap_reader

try:
    import psutil  # необязательно: показывает, какая программа шлёт трафик
except ImportError:
    psutil = None


# ============================================================
# НАСТРОЙКИ
# ============================================================

DEFAULT_TSHARK_PATHS = [
    r"D:\Downloads\Wireshark\tshark.exe",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

WINDOW_SECONDS = 5          # длина одного окна анализа
TRAIN_WINDOWS = 24          # окон для первичного обучения (~2 мин)
HISTORY_LIMIT = 2000        # окон в памяти (~2,7 часа)
RETRAIN_EVERY = 120         # переобучение каждые ~10 минут
NORMAL_BUFFER_SIZE = 720    # переобучение на последнем ~1 часе нормы
CONTAMINATION = 0.03        # ожидаемая доля выбросов при обучении
Z_THRESHOLD = 3.0           # отклонение, при котором ML-тревога засчитывается
Z_STRONG = 6.0              # отклонение, которое — аномалия даже без ML

# Пороги правил (за одно окно в WINDOW_SECONDS секунд).
THRESHOLDS = {
    "port_scan": 25,
    "port_scan_high": 100,
    "host_sweep": 30,
    "syn_flood": 300,
    "rst_storm": 200,
    "icmp_flood": 500,
    "dns_flood": 300,
    "arp_flood": 300,
}

SEVERITY_NAMES = {0: "—", 1: "НИЗКИЙ", 2: "СРЕДНИЙ", 3: "ВЫСОКИЙ"}

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Поля, которые TShark выводит для каждого пакета.
FIELDS = [
    ("size", "frame.len"),
    ("src", "ip.src"),
    ("dst", "ip.dst"),
    ("src6", "ipv6.src"),
    ("dst6", "ipv6.dst"),
    ("tcp_dport", "tcp.dstport"),
    ("udp_dport", "udp.dstport"),
    ("syn", "tcp.flags.syn"),
    ("ack", "tcp.flags.ack"),
    ("rst", "tcp.flags.reset"),
    ("icmp", "icmp.type"),
    ("icmp6", "icmpv6.type"),
    ("dns_resp", "dns.flags.response"),
    ("arp_op", "arp.opcode"),
    ("arp_ip", "arp.src.proto_ipv4"),
    ("arp_mac", "arp.src.hw_mac"),
    # Имена сайтов: из DNS-ответов, HTTPS (SNI) и HTTP.
    ("dns_name", "dns.qry.name"),
    ("dns_a", "dns.a"),
    ("sni", "tls.handshake.extensions_server_name"),
    ("http_host", "http.host"),
]

TOP_TALKERS = 5
NAME_CACHE_LIMIT = 5000

# Понятные названия популярных сервисов по домену.
KNOWN_SERVICES = [
    ("googlevideo.com", "YouTube (видео)"),
    ("youtube.com", "YouTube"),
    ("ytimg.com", "YouTube"),
    ("google", "Google"),
    ("gstatic.com", "Google"),
    ("telegram", "Telegram"),
    ("t.me", "Telegram"),
    ("whatsapp", "WhatsApp"),
    ("discord", "Discord"),
    ("vk.com", "ВКонтакте"),
    ("userapi.com", "ВКонтакте"),
    ("vkuser", "ВКонтакте"),
    ("yandex", "Яндекс"),
    ("twitch", "Twitch"),
    ("steam", "Steam"),
    ("roblox", "Roblox"),
    ("rbxcdn", "Roblox"),
    ("epicgames", "Epic Games"),
    ("microsoft", "Microsoft"),
    ("windowsupdate", "Обновление Windows"),
    ("msedge", "Microsoft Edge"),
    ("live.com", "Microsoft"),
    ("office", "Microsoft Office"),
    ("apple", "Apple"),
    ("icloud", "Apple iCloud"),
    ("netflix", "Netflix"),
    ("nflxvideo", "Netflix"),
    ("spotify", "Spotify"),
    ("tiktok", "TikTok"),
    ("instagram", "Instagram"),
    ("facebook", "Facebook"),
    ("fbcdn", "Facebook"),
    ("twitter", "X (Twitter)"),
    ("x.com", "X (Twitter)"),
    ("github", "GitHub"),
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai CDN"),
    ("amazonaws", "Amazon AWS"),
    ("groq.com", "Groq AI"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("claude.ai", "Claude"),
]


def service_name(domain):
    domain = (domain or "").lower()

    for part, label in KNOWN_SERVICES:
        if part in domain:
            return label

    return ""


def ip_kind(ip):
    """Подпись для адресов, у которых нет имени сайта."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""

    if addr.is_multicast or ip.endswith(".255"):
        return "Служебная рассылка (мультикаст/широковещание)"

    if addr.is_loopback:
        return "Этот компьютер"

    if addr.is_link_local or addr.is_private:
        return "Локальная сеть (роутер или другое устройство)"

    return ""


def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return addr.is_private or addr.is_multicast or addr.is_link_local

FIELD_KEYS = [key for key, _ in FIELDS]

# Признаки, которые видит Isolation Forest.
MODEL_FEATURES = [
    ("packets", "Пакеты"),
    ("bytes", "Байты"),
    ("avg_size", "Средний размер пакета"),
    ("sources", "Источники"),
    ("destinations", "Получатели"),
    ("ports", "Порты назначения"),
    ("tcp", "TCP"),
    ("udp", "UDP"),
    ("icmp", "ICMP"),
    ("syn", "SYN"),
    ("rst", "RST"),
    ("dns", "DNS"),
    ("arp", "ARP"),
    ("max_ports_per_src", "Портов от одного источника"),
]


# ============================================================
# ВСПОМОГАТЕЛЬНОЕ
# ============================================================

def flag_is_set(value):
    value = value.strip().lower()

    if value in ("true", "yes", "set"):
        return True

    if value in ("false", "no", "unset", ""):
        return False

    try:
        return int(value, 0) != 0
    except ValueError:
        return False


def parse_line(line):
    parts = line.split("\t")

    if len(parts) != len(FIELD_KEYS):
        return None

    packet = dict(zip(FIELD_KEYS, parts))

    if not packet["size"].isdigit():
        return None

    return packet


def fmt(value):
    return f"{value:,.0f}".replace(",", " ")


def find_tshark():
    found = shutil.which("tshark")

    if found:
        return found

    for path in DEFAULT_TSHARK_PATHS:
        if os.path.isfile(path):
            return path

    return ""


# Служебные «интерфейсы» Wireshark, которые не являются сетевыми картами.
EXTCAP_NAMES = {
    "ciscodump", "etwdump", "randpkt", "randpktdump", "sshdump",
    "udpdump", "wifidump", "sdjournal", "dpauxmon", "androiddump",
}


def is_capture_device(item):
    device = item.get("device", "").lower().split(".")[0]
    return device not in EXTCAP_NAMES


def is_loopback(item):
    text = (item.get("name", "") + " " + item.get("device", "")).lower()
    return "loopback" in text


def probe_interfaces(tshark_path, numbers, seconds=3):
    """Одновременно слушает несколько интерфейсов `seconds` секунд
    и возвращает, сколько пакетов пришло на каждый."""
    tshark_path = str(tshark_path or "").strip().strip('"')
    results = {}
    processes = {}

    for number in numbers:
        try:
            processes[number] = subprocess.Popen(
                [
                    tshark_path, "-i", str(number), "-n",
                    "-a", f"duration:{seconds}",
                    "-T", "fields", "-e", "frame.len",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
        except OSError as exc:
            results[number] = {"packets": 0, "error": str(exc)}

    for number, process in processes.items():
        try:
            out, err = process.communicate(timeout=seconds + 15)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()

        count = sum(1 for line in (out or "").splitlines() if line.strip())
        error = ""

        if count == 0 and process.returncode not in (0, None):
            lines = [x for x in (err or "").splitlines() if x.strip()]
            error = lines[-1] if lines else ""

        results[number] = {"packets": count, "error": error}

    return results


def list_interfaces(tshark_path):
    tshark_path = str(tshark_path or "").strip().strip('"')

    if not tshark_path or not os.path.isfile(tshark_path):
        raise RuntimeError(
            f"TShark не найден: {tshark_path or 'путь не указан'}"
        )

    result = subprocess.run(
        [tshark_path, "-D"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        creationflags=CREATE_NO_WINDOW,
    )

    items = []

    for line in result.stdout.splitlines():
        match = re.match(
            r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$",
            line,
        )

        if match:
            number, device, name = match.groups()
            items.append({
                "number": number,
                "device": device,
                "name": name or device,
            })

    if not items:
        raise RuntimeError(
            result.stderr.strip()
            or "TShark не вернул список интерфейсов. "
               "Проверь, что установлен Npcap."
        )

    return items


# ============================================================
# ДВИЖОК
# ============================================================

class CyberAIEngine:
    def __init__(self, on_record=None, on_fit=None):
        # on_record(record, session_id) вызывается после
        # каждого окна — например, чтобы сохранить его в базу.
        # on_fit(rows) вызывается после обучения модели —
        # чтобы сохранить «норму» и не обучаться заново.
        self.on_record = on_record
        self.on_fit = on_fit

        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.queue = Queue(maxsize=50000)

        self.process = None
        self.worker = None
        self.running = False
        self.stopping = False

        self.tshark_path = ""
        self.interface = ""
        self.session_id = None

        self._reset_state()

    def _reset_state(self):
        self.history = deque(maxlen=HISTORY_LIMIT)

        self.training = []
        self.normal_buffer = deque(maxlen=NORMAL_BUFFER_SIZE)
        self.model = None
        self.baseline_mean = None
        self.baseline_std = None
        self.windows_since_fit = 0
        self.last_retrain = None

        self.arp_table = {}
        self.names = {}          # IP -> домен (из DNS/HTTPS)
        self.process_names = {}  # PID -> имя программы
        self.latest_talkers = []
        self.stderr_lines = deque(maxlen=30)

        self.live_packets = 0
        self.live_bytes = 0
        self.live_syn = 0

        self.dropped = 0
        self.error = ""
        self.save_error = ""

        # Диагностика: сколько строк прислал TShark и сколько
        # из них не удалось разобрать.
        self.raw_lines = 0
        self.bad_lines = 0
        self.last_bad_line = ""

        # Скорость трафика по секундам (последние 10 минут).
        self.rates = deque(maxlen=600)
        self.sec_packets = 0
        self.sec_bytes = 0
        self.current_rate = 0

        self.baseline_loaded = False

        # Источник: live — TShark, demo — демо-запись, file — файл.
        self.source = "live"
        self.source_label = ""
        self.replay_finished = False
        self.replay_progress = 0.0

        self.started_at = None
        self.ended_at = None

    # --------------------------------------------------------
    # Старт / стоп
    # --------------------------------------------------------

    def start(self, tshark_path, interface, baseline=None):
        tshark_path = str(tshark_path or "").strip().strip('"')
        interface = str(interface or "").strip()

        if not tshark_path or not os.path.isfile(tshark_path):
            raise ValueError(
                "TShark не найден: "
                f"{tshark_path or 'путь не указан'}. "
                "Укажи путь в ⚙️ Настройки → Захват трафика."
            )

        if not interface:
            raise ValueError(
                "Не выбран сетевой интерфейс. Открой "
                "⚙️ Настройки → Захват трафика → «Найти интерфейсы»."
            )

        with self.lock:
            if self.running or self.stopping:
                return False

            self.stop_event = threading.Event()
            self.queue = Queue(maxsize=50000)
            self._reset_state()

            self.tshark_path = tshark_path
            self.interface = interface
            self._load_baseline(baseline)
            self.started_at = datetime.now()
            self.session_id = self.started_at.strftime("%Y%m%d_%H%M%S")

            self.running = True
            self.stopping = False

            self.worker = threading.Thread(
                target=self._run,
                daemon=True,
            )
            self.worker.start()

            return True

    def _load_baseline(self, baseline):
        """Если модель уже обучалась раньше — берём сохранённую
        «норму» и сразу начинаем анализ, без 2 минут обучения."""
        if not baseline:
            return

        width = len(MODEL_FEATURES)
        rows = []

        for row in baseline:
            try:
                values = [float(v) for v in row]
            except (TypeError, ValueError):
                continue

            if len(values) == width:
                rows.append(values)

        rows = rows[-NORMAL_BUFFER_SIZE:]

        if len(rows) < TRAIN_WINDOWS:
            return

        try:
            self._fit(rows, notify=False)
        except Exception:
            self.model = None
            return

        self.normal_buffer.extend(np.array(rows, dtype=float))
        self.baseline_loaded = True

    def start_replay(self, path, source="demo", speed=3.0, label=""):
        """Проигрывает запись .pcap/.pcapng вместо живого захвата.

        speed — во сколько раз быстрее реального времени;
        0 — максимально быстро (анализ файла).
        """
        if not pcap_reader.is_capture_file(path):
            raise ValueError(
                "Это не запись трафика. Нужен файл .pcap или .pcapng "
                "(например, сохранённый в Wireshark)."
            )

        with self.lock:
            if self.running or self.stopping:
                return False

            self.stop_event = threading.Event()
            self.queue = Queue(maxsize=50000)
            self._reset_state()

            self.source = source
            self.source_label = label or os.path.basename(path)
            self.interface = self.source_label
            self.started_at = datetime.now()
            self.session_id = (
                f"{source}_" + self.started_at.strftime("%Y%m%d_%H%M%S")
            )

            self.running = True
            self.stopping = False

            self.worker = threading.Thread(
                target=self._run_replay,
                args=(path, float(speed or 0)),
                daemon=True,
            )
            self.worker.start()

            return True

    def _run_replay(self, path, speed):
        w = WINDOW_SECONDS
        packets = []
        first_ts = None
        window_ts = None
        second_ts = None
        wall_start = time.monotonic()

        # Демо выглядит «живым» (время = сейчас),
        # у файла — настоящее время записи.
        use_wallclock = self.source == "demo"

        def stamp(ts):
            if use_wallclock:
                return datetime.now()
            return datetime.fromtimestamp(ts)

        try:
            # Пакеты читаются по одному — даже большой файл
            # не занимает лишнюю память.
            last_ts = None

            for packet in pcap_reader.iter_packets(path, FIELD_KEYS):
                if self.stop_event.is_set():
                    break

                ts = packet["time"]
                last_ts = ts

                if first_ts is None:
                    first_ts = window_ts = second_ts = ts

                # Ждём, чтобы проигрывать в нужном темпе.
                if speed > 0:
                    while not self.stop_event.is_set():
                        delay = (ts - first_ts) / speed - (
                            time.monotonic() - wall_start
                        )
                        if delay <= 0:
                            break
                        self.stop_event.wait(min(delay, 0.25))

                    if self.stop_event.is_set():
                        break

                # Завершаем прошедшие окна (по времени записи).
                if ts - window_ts > w * 20:
                    window_ts = ts - ((ts - window_ts) % w)

                while ts - window_ts >= w:
                    self._finish_window(packets, stamp(window_ts + w))
                    packets = []
                    window_ts += w

                # Скорость по секундам записи.
                if ts - second_ts > 120:
                    second_ts = ts - ((ts - second_ts) % 1)

                while ts - second_ts >= 1:
                    with self.lock:
                        self.rates.append({
                            "Метка": stamp(second_ts + 1).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "Пакеты/с": self.sec_packets,
                            "Байты/с": self.sec_bytes,
                        })
                        self.current_rate = self.sec_packets
                        self.sec_packets = 0
                        self.sec_bytes = 0
                    second_ts += 1

                packets.append(packet)
                size = int(packet["size"])

                with self.lock:
                    self.raw_lines += 1
                    self.live_packets += 1
                    self.live_bytes += size
                    self.sec_packets += 1
                    self.sec_bytes += size

                    if (
                        flag_is_set(packet["syn"])
                        and not flag_is_set(packet["ack"])
                    ):
                        self.live_syn += 1

                    self.replay_progress = packet.get("progress", 0.0)

            if last_ts is None and not self.stop_event.is_set():
                raise RuntimeError("В записи нет ни одного пакета.")

            if packets and not self.stop_event.is_set():
                self._finish_window(packets, stamp(last_ts))
                packets = []

            with self.lock:
                if not self.stop_event.is_set():
                    self.replay_finished = True
                    self.replay_progress = 1.0

        except Exception as error:
            with self.lock:
                self.error = f"Не удалось прочитать запись: {error}"

        finally:
            with self.lock:
                self.ended_at = datetime.now()
                self.running = False
                self.stopping = False

    def stop(self):
        with self.lock:
            if not self.running:
                return

            self.stopping = True
            self.stop_event.set()
            process = self.process

        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    # --------------------------------------------------------
    # Чтение вывода TShark
    # --------------------------------------------------------

    def _read(self, process):
        try:
            for line in process.stdout:
                if self.stop_event.is_set():
                    break

                try:
                    self.queue.put_nowait(line.rstrip("\r\n"))
                except Full:
                    with self.lock:
                        self.dropped += 1

        except (ValueError, OSError):
            pass

        finally:
            try:
                process.stdout.close()
            except (ValueError, OSError):
                pass

    def _read_stderr(self, process):
        try:
            for line in process.stderr:
                line = line.strip()

                if line:
                    with self.lock:
                        self.stderr_lines.append(line)

        except (ValueError, OSError):
            pass

    def _tshark_error(self):
        with self.lock:
            lines = list(self.stderr_lines)

        detail = " ".join(lines[-3:])
        hint = (
            "Проверь интерфейс в ⚙️ Настройках "
            "и что установлен Npcap."
        )

        if detail:
            return f"TShark остановился: {detail} — {hint}"

        return f"TShark остановился без сообщения об ошибке. {hint}"

    # --------------------------------------------------------
    # Признаки окна
    # --------------------------------------------------------

    @staticmethod
    def _compute(packets):
        f = {
            key: 0
            for key in (
                "packets", "bytes", "tcp", "udp", "icmp",
                "syn", "synack", "rst", "dns", "dns_queries", "arp",
            )
        }

        sources = set()
        destinations = set()
        ports = set()

        ports_by_src = defaultdict(set)
        targets_by_src = defaultdict(set)
        arp_pairs = []

        for p in packets:
            f["packets"] += 1
            f["bytes"] += int(p["size"])

            src = p["src"] or p["src6"]
            dst = p["dst"] or p["dst6"]

            if src:
                sources.add(src)

            if dst:
                destinations.add(dst)

            tcp_port = p["tcp_dport"]
            udp_port = p["udp_dport"]

            if tcp_port.isdigit():
                f["tcp"] += 1
                ports.add(int(tcp_port))

            if udp_port.isdigit():
                f["udp"] += 1
                ports.add(int(udp_port))

            if p["icmp"] or p["icmp6"]:
                f["icmp"] += 1

                is_ping = p["icmp"] == "8" or p["icmp6"] == "128"

                if is_ping and src and dst:
                    targets_by_src[src].add(dst)

            syn = flag_is_set(p["syn"])
            ack = flag_is_set(p["ack"])

            if syn and not ack:
                f["syn"] += 1

                if src and dst:
                    targets_by_src[src].add(dst)

                    if tcp_port.isdigit():
                        ports_by_src[src].add(int(tcp_port))

            elif syn and ack:
                f["synack"] += 1

            if flag_is_set(p["rst"]):
                f["rst"] += 1

            if p["dns_resp"]:
                f["dns"] += 1

                if not flag_is_set(p["dns_resp"]):
                    f["dns_queries"] += 1

            if p["arp_op"]:
                f["arp"] += 1

                if p["arp_ip"] and p["arp_mac"]:
                    arp_pairs.append(
                        (p["arp_ip"], p["arp_mac"].lower())
                    )

        scan_src, scan_ports = max(
            ((s, len(v)) for s, v in ports_by_src.items()),
            key=lambda item: item[1],
            default=(None, 0),
        )

        sweep_src, sweep_targets = max(
            ((s, len(v)) for s, v in targets_by_src.items()),
            key=lambda item: item[1],
            default=(None, 0),
        )

        f["sources"] = len(sources)
        f["destinations"] = len(destinations)
        f["ports"] = len(ports)
        f["avg_size"] = (
            round(f["bytes"] / f["packets"], 1)
            if f["packets"] else 0
        )
        f["max_ports_per_src"] = scan_ports

        extras = {
            "scan_src": scan_src,
            "scan_ports": scan_ports,
            "sweep_src": sweep_src,
            "sweep_targets": sweep_targets,
            "arp_pairs": arp_pairs,
        }

        return f, extras

    def _check_arp(self, pairs):
        conflicts = {}

        for ip, mac in pairs:
            if ip == "0.0.0.0":
                continue

            old = self.arp_table.get(ip)

            if old and old != mac:
                conflicts[ip] = (ip, old, mac)

            self.arp_table[ip] = mac

        return list(conflicts.values())

    # --------------------------------------------------------
    # Правила обнаружения
    # --------------------------------------------------------

    @staticmethod
    def _rules(f, extras, conflicts):
        t = THRESHOLDS
        w = WINDOW_SECONDS
        hits = []

        if extras["scan_ports"] >= t["port_scan"]:
            level = 3 if extras["scan_ports"] >= t["port_scan_high"] else 2
            hits.append((
                level,
                "Возможное сканирование портов: "
                f"{extras['scan_src']} → {fmt(extras['scan_ports'])} "
                f"разных портов за {w} с",
            ))

        if extras["sweep_targets"] >= t["host_sweep"]:
            hits.append((
                2,
                "Возможный обход сети: "
                f"{extras['sweep_src']} обратился к "
                f"{fmt(extras['sweep_targets'])} разным узлам за {w} с",
            ))

        if (
            f["syn"] >= t["syn_flood"]
            and f["syn"] >= 0.5 * f["packets"]
        ):
            hits.append((
                3,
                f"Всплеск SYN-пакетов: {fmt(f['syn'])} "
                f"(ответов SYN-ACK: {fmt(f['synack'])}) — "
                "похоже на SYN-flood",
            ))

        if f["rst"] >= t["rst_storm"]:
            hits.append((
                2,
                f"Много TCP RST: {fmt(f['rst'])} за {w} с — "
                "часто бывает при сканировании закрытых портов",
            ))

        if f["icmp"] >= t["icmp_flood"]:
            hits.append((
                2,
                f"ICMP-флуд: {fmt(f['icmp'])} пакетов за {w} с",
            ))

        if f["dns_queries"] >= t["dns_flood"]:
            hits.append((
                2,
                f"Очень много DNS-запросов: {fmt(f['dns_queries'])} "
                f"за {w} с (флуд или DNS-туннель)",
            ))

        if f["arp"] >= t["arp_flood"]:
            hits.append((
                2,
                f"Много ARP-пакетов: {fmt(f['arp'])} за {w} с — "
                "возможное ARP-сканирование",
            ))

        for ip, old, new in conflicts:
            hits.append((
                3,
                f"IP {ip} сменил MAC: {old} → {new} — "
                "возможный ARP-спуфинг",
            ))

        return hits

    # --------------------------------------------------------
    # Машинное обучение
    # --------------------------------------------------------

    @staticmethod
    def _vector(f):
        # log1p сглаживает огромные всплески трафика,
        # чтобы модель была стабильнее.
        return np.log1p(
            np.array([f[key] for key, _ in MODEL_FEATURES], dtype=float)
        )

    def _fit(self, rows, notify=True):
        x = np.array(rows, dtype=float)

        model = IsolationForest(
            n_estimators=150,
            contamination=CONTAMINATION,
            random_state=42,
        )
        model.fit(x)

        self.model = model
        self.baseline_mean = x.mean(axis=0)
        self.baseline_std = np.maximum(x.std(axis=0), 0.25)
        self.windows_since_fit = 0
        self.last_retrain = datetime.now()

        if notify and self.on_fit is not None and self.source == "live":
            try:
                self.on_fit([[round(float(v), 5) for v in row] for row in x])
            except Exception as exc:
                with self.lock:
                    self.save_error = str(exc)

    def _deviations(self, vec, f, threshold=Z_THRESHOLD):
        if self.baseline_mean is None:
            return []

        z = (vec - self.baseline_mean) / self.baseline_std
        found = []

        for i, (key, label) in enumerate(MODEL_FEATURES):
            value = f[key]

            if z[i] < threshold:
                continue

            if key != "avg_size" and value < 20:
                continue

            typical = float(np.expm1(self.baseline_mean[i]))
            ratio = (value + 1) / (typical + 1)

            found.append((
                float(z[i]),
                f"{label}: {fmt(value)} "
                f"(обычно ≈ {fmt(typical)}, ×{ratio:.1f})",
            ))

        found.sort(reverse=True)

        return [text for _, text in found[:3]]

    # --------------------------------------------------------
    # Завершение окна
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Откуда трафик: IP -> сайт -> программа
    # --------------------------------------------------------

    def _remember_name(self, ip, name):
        ip = (ip or "").strip()
        name = (name or "").strip().rstrip(".").lower()

        if not ip or not name:
            return

        if len(self.names) >= NAME_CACHE_LIMIT and ip not in self.names:
            self.names.pop(next(iter(self.names)))

        self.names[ip] = name

    def _learn_names(self, packets):
        for p in packets:
            if p["dns_name"] and p["dns_a"]:
                self._remember_name(p["dns_a"], p["dns_name"])

            dst = p["dst"] or p["dst6"]

            if p["sni"] and dst:
                self._remember_name(dst, p["sni"])

            if p["http_host"] and dst:
                self._remember_name(dst, p["http_host"].split(":")[0])

    def _process_map(self):
        """Удалённый IP -> программа на этом компьютере (через psutil)."""
        if psutil is None:
            return {}

        result = {}

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return {}

        for conn in connections:
            if not conn.raddr or not conn.pid:
                continue

            name = self.process_names.get(conn.pid)

            if name is None:
                try:
                    name = psutil.Process(conn.pid).name()
                except Exception:
                    name = ""

                if len(self.process_names) > 2000:
                    self.process_names.clear()

                self.process_names[conn.pid] = name

            if name:
                result.setdefault(conn.raddr.ip, name)

        return result

    def _talkers(self, packets):
        """Определяет, с какими адресами общается компьютер,
        и возвращает топ по количеству пакетов."""
        if not packets:
            return []

        counts4 = defaultdict(int)
        counts6 = defaultdict(int)

        for p in packets:
            for ip in (p["src"], p["dst"]):
                if ip:
                    counts4[ip] += 1
            for ip in (p["src6"], p["dst6"]):
                if ip:
                    counts6[ip] += 1

        # «Этот компьютер» — адрес, который встречается чаще всех.
        me = set()
        if counts4:
            me.add(max(counts4, key=counts4.get))
        if counts6:
            me.add(max(counts6, key=counts6.get))

        stats = {}

        for p in packets:
            src = p["src"] or p["src6"]
            dst = p["dst"] or p["dst6"]

            if not src or not dst:
                continue

            if src in me and dst not in me:
                remote, outgoing = dst, True
            elif dst in me and src not in me:
                remote, outgoing = src, False
            elif is_private_ip(src) and not is_private_ip(dst):
                remote, outgoing = dst, True
            else:
                remote, outgoing = src, False

            item = stats.setdefault(remote, {
                "packets": 0, "bytes": 0, "ports": defaultdict(int),
            })
            item["packets"] += 1
            item["bytes"] += int(p["size"])

            port = p["tcp_dport"] if outgoing else ""
            port = port or (p["udp_dport"] if outgoing else "")

            if port.isdigit():
                item["ports"][int(port)] += 1

        total = sum(x["packets"] for x in stats.values()) or 1
        top = sorted(
            stats.items(),
            key=lambda kv: kv[1]["packets"],
            reverse=True,
        )[:TOP_TALKERS]

        programs = self._process_map() if self.source == "live" else {}
        result = []

        for ip, item in top:
            domain = self.names.get(ip, "")
            service = service_name(domain)
            ports = sorted(
                item["ports"], key=item["ports"].get, reverse=True
            )[:3]

            result.append({
                "Адрес": ip,
                "Сайт": domain or ip_kind(ip) or "неизвестно",
                "Сервис": service,
                "Программа": programs.get(ip, ""),
                "Пакеты": item["packets"],
                "Байты": item["bytes"],
                "Доля": round(item["packets"] * 100 / total),
                "Порты": ", ".join(str(x) for x in ports),
            })

        return result

    @staticmethod
    def talker_label(item):
        if not item:
            return ""

        name = item.get("Сервис") or item.get("Сайт") or item.get("Адрес")

        if item.get("Сервис") and item.get("Сайт") not in ("", "неизвестно"):
            name = f"{item['Сервис']} ({item['Сайт']})"

        if name != item.get("Адрес"):
            name += f" [{item.get('Адрес')}]"

        if item.get("Программа"):
            name += f", программа {item['Программа']}"

        return name

    def _finish_window(self, packets, stamp=None):
        self._learn_names(packets)
        talkers = self._talkers(packets)

        f, extras = self._compute(packets)
        conflicts = self._check_arp(extras["arp_pairs"])
        vec = self._vector(f)

        rules = self._rules(f, extras, conflicts)
        rules.sort(key=lambda item: item[0], reverse=True)

        reasons = [text for _, text in rules]
        severity = max((level for level, _ in rules), default=0)
        score = None

        if self.model is None:
            status = "ОБУЧЕНИЕ"

            # Окна с явными признаками атак не берём в обучение.
            if not rules:
                self.training.append(vec)

            if len(self.training) >= TRAIN_WINDOWS:
                self._fit(self.training)
                self.normal_buffer.extend(self.training)

            if rules:
                status = "АНОМАЛИЯ"

        else:
            x = vec.reshape(1, -1)

            ml_flag = self.model.predict(x)[0] == -1
            score = round(float(self.model.decision_function(x)[0]), 4)

            # ML-тревога засчитывается, только если есть
            # понятная причина — так меньше ложных срабатываний.
            # Isolation Forest плохо замечает ОЧЕНЬ большие всплески,
            # если обычный трафик однородный, поэтому сильные
            # отклонения от нормы считаем аномалией и без него.
            if ml_flag:
                deviations = self._deviations(vec, f)
            else:
                deviations = self._deviations(vec, f, Z_STRONG)

            if deviations:
                reasons.extend(deviations)
                severity = max(
                    severity,
                    2 if len(deviations) >= 2 else 1,
                )

            status = "АНОМАЛИЯ" if severity > 0 else "НОРМА"

            if status == "НОРМА":
                self.normal_buffer.append(vec)

            self.windows_since_fit += 1

            if (
                self.windows_since_fit >= RETRAIN_EVERY
                and len(self.normal_buffer) >= TRAIN_WINDOWS
            ):
                self._fit(list(self.normal_buffer))

        if status == "АНОМАЛИЯ" and talkers:
            top = talkers[0]
            reasons.append(
                "Основной источник трафика: "
                f"{self.talker_label(top)} — {top['Доля']}% пакетов"
            )

        now = stamp or datetime.now()

        record = {
            "Метка": now.strftime("%Y-%m-%d %H:%M:%S"),
            "Время": now.strftime("%H:%M:%S"),
            "Пакеты": f["packets"],
            "Байты": f["bytes"],
            "SYN": f["syn"],
            "TCP": f["tcp"],
            "UDP": f["udp"],
            "ICMP": f["icmp"],
            "DNS": f["dns"],
            "ARP": f["arp"],
            "RST": f["rst"],
            "Источники": f["sources"],
            "Получатели": f["destinations"],
            "Порты": f["ports"],
            "Статус": status,
            "Уровень": SEVERITY_NAMES[severity],
            "AI Score": score,
            "Причины": " | ".join(reasons),
            "Главный источник": (
                self.talker_label(talkers[0]) if talkers else ""
            ),
            "Источники трафика": talkers,
        }

        with self.lock:
            self.history.append(record)
            self.latest_talkers = talkers
            self.live_packets = 0
            self.live_bytes = 0
            self.live_syn = 0
            session_id = self.session_id

        if self.on_record is not None:
            try:
                self.on_record(record, session_id)
                with self.lock:
                    self.save_error = ""
            except Exception as exc:
                with self.lock:
                    self.save_error = str(exc)

    # --------------------------------------------------------
    # Главный цикл
    # --------------------------------------------------------

    def _run(self):
        command = [
            self.tshark_path,
            "-i", self.interface,
            "-l", "-n", "-Q",
            "-T", "fields",
            "-E", "separator=/t",
            "-E", "occurrence=f",
        ]

        for _, field in FIELDS:
            command += ["-e", field]

        packets = []

        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=CREATE_NO_WINDOW,
                )
            except FileNotFoundError:
                raise RuntimeError(
                    "Не удалось запустить TShark: файл не найден "
                    f"({self.tshark_path})."
                )
            except PermissionError:
                raise RuntimeError(
                    "Нет прав на запуск TShark. Попробуй запустить "
                    "командную строку от имени администратора."
                )

            with self.lock:
                self.process = process

            threading.Thread(
                target=self._read,
                args=(process,),
                daemon=True,
            ).start()

            stderr_reader = threading.Thread(
                target=self._read_stderr,
                args=(process,),
                daemon=True,
            )
            stderr_reader.start()

            window_start = time.monotonic()
            second_start = window_start

            while not self.stop_event.is_set():
                try:
                    line = self.queue.get(timeout=0.1)
                except Empty:
                    line = None

                    if process.poll() is not None and self.queue.empty():
                        stderr_reader.join(timeout=1.0)
                        raise RuntimeError(self._tshark_error())

                if line is not None:
                    packet = parse_line(line)

                    with self.lock:
                        self.raw_lines += 1

                        if packet is None:
                            self.bad_lines += 1
                            self.last_bad_line = line[:200]

                    if packet is not None:
                        packets.append(packet)
                        size = int(packet["size"])

                        with self.lock:
                            self.live_packets += 1
                            self.live_bytes += size
                            self.sec_packets += 1
                            self.sec_bytes += size

                            if (
                                flag_is_set(packet["syn"])
                                and not flag_is_set(packet["ack"])
                            ):
                                self.live_syn += 1

                now_mono = time.monotonic()

                if now_mono - second_start >= 1.0:
                    with self.lock:
                        self.rates.append({
                            "Метка": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "Пакеты/с": self.sec_packets,
                            "Байты/с": self.sec_bytes,
                        })
                        self.current_rate = self.sec_packets
                        self.sec_packets = 0
                        self.sec_bytes = 0

                    second_start = now_mono

                if time.monotonic() - window_start >= WINDOW_SECONDS:
                    self._finish_window(packets)
                    packets = []
                    window_start = time.monotonic()

        except Exception as error:
            with self.lock:
                if not self.stop_event.is_set():
                    self.error = str(error)

        finally:
            self.stop_event.set()

            process = self.process

            if process is not None:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass

                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

            # Учитываем пакеты последнего неполного окна.
            while True:
                try:
                    packet = parse_line(self.queue.get_nowait())
                except Empty:
                    break

                if packet is not None:
                    packets.append(packet)

            if packets:
                try:
                    self._finish_window(packets)
                except Exception as error:
                    with self.lock:
                        self.error = str(error)

            with self.lock:
                self.ended_at = datetime.now()
                self.running = False
                self.stopping = False
                self.process = None

    # --------------------------------------------------------
    # Данные для интерфейса
    # --------------------------------------------------------

    def snapshot(self):
        with self.lock:
            return {
                "running": self.running,
                "stopping": self.stopping,
                "history": list(self.history),
                "training_count": len(self.training),
                "train_target": TRAIN_WINDOWS,
                "trained": self.model is not None,
                "last_retrain": self.last_retrain,
                "live_packets": self.live_packets,
                "live_bytes": self.live_bytes,
                "live_syn": self.live_syn,
                "dropped": self.dropped,
                "error": self.error,
                "save_error": self.save_error,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "session_id": self.session_id,
                "interface": self.interface,
                "window_seconds": WINDOW_SECONDS,
                "raw_lines": self.raw_lines,
                "bad_lines": self.bad_lines,
                "last_bad_line": self.last_bad_line,
                "rates": list(self.rates),
                "current_rate": self.current_rate,
                "baseline_loaded": self.baseline_loaded,
                "latest_talkers": list(self.latest_talkers),
                "psutil": psutil is not None,
                "source": self.source,
                "source_label": self.source_label,
                "replay_finished": self.replay_finished,
                "replay_progress": self.replay_progress,
            }
