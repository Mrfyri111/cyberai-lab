"""
CyberAI Lab — чтение записей трафика (.pcap / .pcapng) без Wireshark.

Нужен для облачной версии и для анализа загруженных файлов:
разбирает пакеты на чистом Python и выдаёт те же поля,
что движок получает от TShark (см. FIELDS в cyberai_engine.py).

Поддерживается: Ethernet (+VLAN), Linux cooked (SLL/SLL2), raw IP,
loopback; IPv4/IPv6, TCP, UDP, ICMP/ICMPv6, ARP, DNS, TLS SNI, HTTP Host.
"""

import ipaddress
import struct


# ============================================================
# ЧТЕНИЕ ФАЙЛА
# ============================================================

def _iter_pcap(data):
    magic = data[:4]

    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Неизвестный формат файла.")

    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    divisor = 1e9 if nano else 1e6
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    offset = 24

    while offset + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        frame = data[offset:offset + incl]
        offset += incl

        if len(frame) < incl:
            break

        yield sec + frac / divisor, linktype, frame, orig


def _iter_pcapng(data):
    offset = 0
    endian = "<"
    interfaces = []

    while offset + 12 <= len(data):
        block_type = struct.unpack(endian + "I", data[offset:offset + 4])[0]

        if block_type == 0x0A0D0D0A:
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []

        length = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]

        if length < 12 or offset + length > len(data):
            break

        body = data[offset + 8:offset + length - 4]

        if block_type == 1 and len(body) >= 8:
            # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            resolution = 1e6
            pos = 8

            while pos + 4 <= len(body):
                code, size = struct.unpack(endian + "HH", body[pos:pos + 4])
                value = body[pos + 4:pos + 4 + size]

                if code == 0:
                    break

                if code == 9 and value:
                    raw = value[0]
                    resolution = (
                        2 ** (raw & 0x7F) if raw & 0x80 else 10 ** raw
                    )

                pos += 4 + ((size + 3) & ~3)

            interfaces.append((linktype, resolution))

        elif block_type == 6 and len(body) >= 20:
            # Enhanced Packet Block
            iface, high, low, incl, orig = struct.unpack(
                endian + "IIIII", body[:20]
            )

            if iface < len(interfaces):
                linktype, resolution = interfaces[iface]
                ts = ((high << 32) | low) / resolution
                yield ts, linktype, body[20:20 + incl], orig

        elif block_type == 3 and len(body) >= 4 and interfaces:
            # Simple Packet Block (без времени)
            orig = struct.unpack(endian + "I", body[:4])[0]
            linktype, _ = interfaces[0]
            yield 0.0, linktype, body[4:4 + orig], orig

        elif block_type == 2 and len(body) >= 20:
            # Устаревший Packet Block
            iface = struct.unpack(endian + "H", body[:2])[0]
            high, low, incl, orig = struct.unpack(endian + "IIII", body[4:20])

            if iface < len(interfaces):
                linktype, resolution = interfaces[iface]
                ts = ((high << 32) | low) / resolution
                yield ts, linktype, body[20:20 + incl], orig

        offset += length


def iter_frames(path):
    """(время, тип канала, байты кадра, исходная длина) для каждого пакета."""
    with open(path, "rb") as file:
        data = file.read()

    if data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
    else:
        yield from _iter_pcap(data)


# ============================================================
# РАЗБОР ПАКЕТА
# ============================================================

def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def _dns_name(payload, offset, depth=0):
    labels = []

    while offset < len(payload) and depth < 20:
        size = payload[offset]

        if size == 0:
            return ".".join(labels), offset + 1

        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer = ((size & 0x3F) << 8) | payload[offset + 1]
            name, _ = _dns_name(payload, pointer, depth + 1)
            labels.append(name)
            return ".".join(x for x in labels if x), offset + 2

        labels.append(
            payload[offset + 1:offset + 1 + size].decode("ascii", "replace")
        )
        offset += 1 + size

    return ".".join(labels), offset


def _parse_dns(payload, out):
    if len(payload) < 12:
        return

    flags, qd, an = struct.unpack(">HHH", payload[2:8])
    out["dns_resp"] = "True" if flags & 0x8000 else "False"
    offset = 12

    for index in range(qd):
        name, offset = _dns_name(payload, offset)
        offset += 4

        if index == 0:
            out["dns_name"] = name

    for _ in range(an):
        if offset >= len(payload):
            break

        _, offset = _dns_name(payload, offset)

        if offset + 10 > len(payload):
            break

        rtype, _, _, rdlen = struct.unpack(">HHIH", payload[offset:offset + 10])
        offset += 10

        if rtype == 1 and rdlen == 4 and not out["dns_a"]:
            out["dns_a"] = str(ipaddress.IPv4Address(payload[offset:offset + 4]))

        offset += rdlen


def _parse_tls_sni(payload):
    # TLS record: тип 22 (handshake), ClientHello (1)
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return ""

    try:
        pos = 9 + 2 + 32                       # версия + random
        pos += 1 + payload[pos]                # session id
        pos += 2 + struct.unpack(">H", payload[pos:pos + 2])[0]  # шифры
        pos += 1 + payload[pos]                # сжатие
        end = pos + 2 + struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2

        while pos + 4 <= min(end, len(payload)):
            ext_type, ext_len = struct.unpack(">HH", payload[pos:pos + 4])
            pos += 4

            if ext_type == 0:  # server_name
                name_len = struct.unpack(">H", payload[pos + 3:pos + 5])[0]
                return payload[pos + 5:pos + 5 + name_len].decode("ascii", "replace")

            pos += ext_len
    except (IndexError, struct.error):
        return ""

    return ""


HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")


def _parse_http_host(payload):
    if not payload.startswith(HTTP_METHODS):
        return ""

    head = payload[:2048]
    index = head.lower().find(b"\r\nhost:")

    if index < 0:
        return ""

    line = head[index + 7:].split(b"\r\n", 1)[0]
    return line.strip().decode("ascii", "replace")


def _parse_transport(proto, payload, out):
    if proto == 6 and len(payload) >= 20:
        sport, dport = struct.unpack(">HH", payload[:4])
        flags = payload[13]
        out["tcp_dport"] = str(dport)
        out["syn"] = "True" if flags & 0x02 else "False"
        out["ack"] = "True" if flags & 0x10 else "False"
        out["rst"] = "True" if flags & 0x04 else "False"

        data = payload[(payload[12] >> 4) * 4:]

        if data:
            sni = _parse_tls_sni(data)

            if sni:
                out["sni"] = sni
            else:
                out["http_host"] = _parse_http_host(data)

    elif proto == 17 and len(payload) >= 8:
        sport, dport = struct.unpack(">HH", payload[:4])
        out["udp_dport"] = str(dport)

        if sport == 53 or dport == 53:
            _parse_dns(payload[8:], out)

    elif proto == 1 and payload:
        out["icmp"] = str(payload[0])

    elif proto == 58 and payload:
        out["icmp6"] = str(payload[0])


def _parse_ipv4(packet, out):
    if len(packet) < 20:
        return

    ihl = (packet[0] & 0x0F) * 4
    proto = packet[9]
    out["src"] = str(ipaddress.IPv4Address(packet[12:16]))
    out["dst"] = str(ipaddress.IPv4Address(packet[16:20]))

    fragment_offset = struct.unpack(">H", packet[6:8])[0] & 0x1FFF

    if fragment_offset == 0:
        _parse_transport(proto, packet[ihl:], out)


def _parse_ipv6(packet, out):
    if len(packet) < 40:
        return

    out["src6"] = str(ipaddress.IPv6Address(packet[8:24]))
    out["dst6"] = str(ipaddress.IPv6Address(packet[24:40]))

    proto = packet[6]
    offset = 40

    # Пропускаем заголовки расширений.
    for _ in range(8):
        if proto in (0, 43, 60) and offset + 2 <= len(packet):
            proto, size = packet[offset], (packet[offset + 1] + 1) * 8
            offset += size
        elif proto == 44 and offset + 8 <= len(packet):
            proto = packet[offset]
            offset += 8
        else:
            break

    _parse_transport(proto, packet[offset:], out)


def _parse_arp(packet, out):
    if len(packet) < 28:
        return

    out["arp_op"] = str(struct.unpack(">H", packet[6:8])[0])
    out["arp_mac"] = _mac(packet[8:14])
    out["arp_ip"] = str(ipaddress.IPv4Address(packet[14:18]))


def _parse_ethertype(ethertype, packet, out):
    if ethertype == 0x0800:
        _parse_ipv4(packet, out)
    elif ethertype == 0x86DD:
        _parse_ipv6(packet, out)
    elif ethertype == 0x0806:
        _parse_arp(packet, out)


def dissect(linktype, frame, orig_len, keys):
    """Возвращает словарь с полями `keys` (строки, как у TShark)."""
    out = dict.fromkeys(keys, "")
    out["size"] = str(orig_len or len(frame))

    try:
        if linktype == 1 and len(frame) >= 14:          # Ethernet
            ethertype = struct.unpack(">H", frame[12:14])[0]
            offset = 14

            while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
                ethertype = struct.unpack(">H", frame[offset + 2:offset + 4])[0]
                offset += 4

            _parse_ethertype(ethertype, frame[offset:], out)

        elif linktype in (101, 12, 14):                  # raw IP
            version = frame[0] >> 4 if frame else 0
            _parse_ethertype(0x0800 if version == 4 else 0x86DD, frame, out)

        elif linktype == 113 and len(frame) >= 16:       # Linux SLL
            ethertype = struct.unpack(">H", frame[14:16])[0]
            _parse_ethertype(ethertype, frame[16:], out)

        elif linktype == 276 and len(frame) >= 20:       # Linux SLL2
            ethertype = struct.unpack(">H", frame[0:2])[0]
            _parse_ethertype(ethertype, frame[20:], out)

        elif linktype in (0, 108) and len(frame) >= 4:   # loopback
            family = struct.unpack("<I", frame[:4])[0]

            if family not in (2, 24, 28, 30):
                family = struct.unpack(">I", frame[:4])[0]

            _parse_ethertype(0x0800 if family == 2 else 0x86DD, frame[4:], out)

    except (IndexError, struct.error, ValueError):
        pass

    return out


def iter_packets(path, keys):
    """Все пакеты файла: словарь полей + время в секундах (ключ 'time')."""
    for ts, linktype, frame, orig in iter_frames(path):
        packet = dissect(linktype, frame, orig, keys)
        packet["time"] = ts
        yield packet


def is_capture_file(path):
    try:
        with open(path, "rb") as file:
            magic = file.read(4)
    except OSError:
        return False

    return magic in (
        b"\x0a\x0d\x0d\x0a",
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    )
