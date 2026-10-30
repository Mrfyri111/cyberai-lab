"""
CyberAI Lab — генератор демо-трафика.

Создаёт запись .pcap с обычной домашней сетью и несколькими
«атаками», чтобы показать работу программы без Wireshark
(например, в облачной версии по ссылке).

Сценарий (время записи):
  0:00–2:30  обычный трафик: YouTube, Discord, Steam, Telegram, Google
  2:35       сканирование портов с 192.168.1.66
  3:20       резкая загрузка с YouTube (всплеск ×20)
  4:05       ARP-спуфинг: «роутер» с чужим MAC-адресом
  4:40       SYN-flood с сотен поддельных адресов
  5:10–5:40  снова обычный трафик
"""

import ipaddress
import random
import struct


ME_IP = "192.168.1.10"
ME_MAC = bytes.fromhex("3c7c3f1a2b10")
ROUTER_IP = "192.168.1.1"
ROUTER_MAC = bytes.fromhex("c8d3ffa01b01")
ATTACKER_IP = "192.168.1.66"
ATTACKER_MAC = bytes.fromhex("de11ad66beef")

SITES = [
    # домен, IP, «вес» трафика
    ("rr4---sn-n8v7kn7s.googlevideo.com", "173.194.183.42", 6),
    ("www.youtube.com", "142.250.74.110", 2),
    ("gateway.discord.gg", "162.159.135.234", 2),
    ("steamcommunity.com", "23.66.141.16", 1),
    ("web.telegram.org", "149.154.167.99", 2),
    ("www.google.com", "142.250.74.4", 1),
    ("api.groq.com", "104.18.40.181", 1),
]

DURATION = 340
BASE_RATE = 45  # пакетов в секунду


# ============================================================
# СБОРКА ПАКЕТОВ
# ============================================================

def _ip(address):
    return ipaddress.IPv4Address(address).packed


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _eth(src_mac, dst_mac, ethertype, payload):
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def _ipv4(src, dst, proto, payload, total_len=None):
    length = total_len or 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, length, random.randint(0, 65535),
        0x4000, 64, proto, 0, _ip(src), _ip(dst),
    )
    header = header[:10] + struct.pack(">H", _checksum(header)) + header[12:]
    return header + payload


def _tcp(sport, dport, flags, payload=b""):
    return struct.pack(
        ">HHIIBBHHH", sport, dport, random.randint(0, 2**32 - 1), 0,
        5 << 4, flags, 64240, 0, 0,
    ) + payload


def _udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_name(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def _dns(name, answer_ip=None):
    txid = random.randint(0, 65535)
    question = _dns_name(name) + struct.pack(">HH", 1, 1)

    if answer_ip is None:
        return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question

    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + _ip(answer_ip)
    return struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def _client_hello(server_name):
    name = server_name.encode()
    sni = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack(">HH", 0, len(sni)) + sni
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + struct.pack(">H", 2) + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    payload = struct.pack(
        ">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
        sender_mac, _ip(sender_ip), target_mac, _ip(target_ip),
    )
    return _eth(sender_mac, target_mac, 0x0806, payload)


# ============================================================
# СЦЕНАРИЙ
# ============================================================

def _normal_second(t, rate, out, sites_weighted):
    for _ in range(rate):
        domain, ip, _ = random.choice(sites_weighted)
        ts = t + random.random()
        port = random.randint(49152, 65000)

        if random.random() < 0.65:
            # входящие данные (большие пакеты)
            size = random.randint(900, 1514)
            frame = _eth(ROUTER_MAC, ME_MAC, 0x0800,
                         _ipv4(ip, ME_IP, 6, _tcp(443, port, 0x18),
                               total_len=size - 14))
        else:
            # исходящие подтверждения (маленькие)
            size = random.randint(54, 120)
            frame = _eth(ME_MAC, ROUTER_MAC, 0x0800,
                         _ipv4(ME_IP, ip, 6, _tcp(port, 443, 0x10),
                               total_len=size - 14))

        out.append((ts, frame, size))


def _visit(t, domain, ip, out):
    """DNS-запрос, ответ и начало HTTPS-соединения с сайтом."""
    port = random.randint(49152, 65000)
    query = _udp(port, 53, _dns(domain))
    reply = _udp(53, port, _dns(domain, ip))
    hello = _client_hello(domain)

    for offset, frame in (
        (0.00, _eth(ME_MAC, ROUTER_MAC, 0x0800, _ipv4(ME_IP, ROUTER_IP, 17, query))),
        (0.02, _eth(ROUTER_MAC, ME_MAC, 0x0800, _ipv4(ROUTER_IP, ME_IP, 17, reply))),
        (0.05, _eth(ME_MAC, ROUTER_MAC, 0x0800, _ipv4(ME_IP, ip, 6, _tcp(port, 443, 0x02)))),
        (0.08, _eth(ROUTER_MAC, ME_MAC, 0x0800, _ipv4(ip, ME_IP, 6, _tcp(443, port, 0x12)))),
        (0.09, _eth(ME_MAC, ROUTER_MAC, 0x0800, _ipv4(ME_IP, ip, 6, _tcp(port, 443, 0x18, hello)))),
    ):
        out.append((t + offset, frame, len(frame)))


def build_packets(seed=7):
    random.seed(seed)
    out = []
    weighted = [s for s in SITES for _ in range(s[2])]

    # Узнаём имена сайтов в начале и время от времени повторно.
    for i, (domain, ip, _) in enumerate(SITES):
        _visit(0.5 + i * 0.3, domain, ip, out)

    for t in range(DURATION):
        rate = BASE_RATE + random.randint(-12, 12)

        # Всплеск загрузки с YouTube
        if 200 <= t < 208:
            youtube = [SITES[0]]
            _normal_second(t, rate * 20, out, youtube)

        _normal_second(t, rate, out, weighted)

        if t % 40 == 20:
            domain, ip, _ = random.choice(SITES)
            _visit(t + 0.4, domain, ip, out)

        # Обычный ARP-ответ роутера
        if t % 30 == 5:
            out.append((t + 0.3, _arp_reply(ROUTER_MAC, ROUTER_IP, ME_MAC, ME_IP), 42))

    # Сканирование портов: 400 портов за ~4 с + ответы RST
    for i, port in enumerate(random.sample(range(1, 10000), 400)):
        ts = 155 + i * 0.01
        syn = _eth(ATTACKER_MAC, ME_MAC, 0x0800,
                   _ipv4(ATTACKER_IP, ME_IP, 6, _tcp(51515, port, 0x02)))
        rst = _eth(ME_MAC, ATTACKER_MAC, 0x0800,
                   _ipv4(ME_IP, ATTACKER_IP, 6, _tcp(port, 51515, 0x14)))
        out.append((ts, syn, len(syn)))
        out.append((ts + 0.002, rst, len(rst)))

    # ARP-спуфинг: 192.168.1.1 вдруг отвечает с MAC атакующего
    for i in range(6):
        ts = 245 + i * 0.5
        out.append((ts, _arp_reply(ATTACKER_MAC, ROUTER_IP, ME_MAC, ME_IP), 42))

    # SYN-flood: 1500 SYN с поддельных адресов за 4 с
    for i in range(1500):
        ts = 280 + i * 0.0027
        fake = f"{random.randint(11, 220)}.{random.randint(0, 255)}." \
               f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        syn = _eth(ROUTER_MAC, ME_MAC, 0x0800,
                   _ipv4(fake, ME_IP, 6, _tcp(random.randint(1024, 65000), 80, 0x02)))
        out.append((ts, syn, len(syn)))

    out.sort(key=lambda item: item[0])
    return out


def write_demo_pcap(path, start_time=1_700_000_000.0):
    """Записывает демо-трафик в .pcap. Крупные пакеты хранятся
    только с заголовками (как при snaplen), поэтому файл маленький."""
    packets = build_packets()
    snaplen = 256

    with open(path, "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))

        for ts, frame, size in packets:
            stamp = start_time + ts
            sec = int(stamp)
            usec = int(round((stamp - sec) * 1e6)) % 1_000_000
            data = frame[:snaplen]
            file.write(struct.pack("<IIII", sec, usec, len(data), max(size, len(frame))))
            file.write(data)

    return len(packets)
