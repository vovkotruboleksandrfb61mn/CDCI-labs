"""Прозорий TCP-проксі-сніфер: моделює зловмисника на шляху «клієнт-сервер».

Слухає на LISTEN_PORT, з'єднується з SERVER_PORT і пересилає байти в обидва
боки, друкуючи їх у форматі hex+ASCII. Для відкритого Modbus видно PDU
(код функції, значення регістрів); для TLS видно лише шифротекст.

    python sniffer.py --listen 1600 --server 1502 --out data/sniff.txt
"""
from __future__ import annotations

import argparse
import socket
import threading


def hexdump(data: bytes, prefix: str) -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix} {off:04x}  {hexs:<47}  {text}")
    return "\n".join(lines)


def pump(src: socket.socket, dst: socket.socket, label: str, out) -> None:
    while True:
        try:
            data = src.recv(4096)
        except OSError:
            break
        if not data:
            break
        out.write(f"[{label}] {len(data)} байт\n{hexdump(data, label)}\n")
        out.flush()
        try:
            dst.sendall(data)
        except OSError:
            break
    dst.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=1600)
    ap.add_argument("--server", type=int, default=1502)
    ap.add_argument("--out", default="data/sniff.txt")
    a = ap.parse_args()

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.listen))
    ls.listen(1)
    print(f"sniffer: 127.0.0.1:{a.listen} -> 127.0.0.1:{a.server}, лог у {a.out}")

    out = open(a.out, "w")
    client, _ = ls.accept()
    server = socket.create_connection(("127.0.0.1", a.server))
    t1 = threading.Thread(target=pump, args=(client, server, "C->S", out))
    t2 = threading.Thread(target=pump, args=(server, client, "S->C", out))
    t1.start(); t2.start()
    t1.join(); t2.join()
    out.close()
    print("sniffer: з'єднання закрито")


if __name__ == "__main__":
    main()
