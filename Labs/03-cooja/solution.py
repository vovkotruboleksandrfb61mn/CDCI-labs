"""ЛР3: обробка журналу Cooja (data/lab3-run.log) для мережі 1 sink + 7 sender.

Рахує середню споживану потужність кожного вузла за даними energest, що їх
збирає приймач (udp-sink), за тими самими формулами, що й Collect View
(tools/collect-view, клас SensorData): потужність = тики * P / (CPU+LPM).

    ../../.venv/bin/python solution.py          # з data/lab3-run.log
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
LOG = HERE / "data" / "lab3-run.log"
ASSETS = HERE / "assets"
DATA = HERE / "data"

# Константи Sky-мота з SensorInfo.java
VOLTAGE = 3.0
POWER_CPU = 1.800 * VOLTAGE
POWER_LPM = 0.0545 * VOLTAGE
POWER_TRANSMIT = 17.7 * VOLTAGE
POWER_LISTEN = 20.0 * VOLTAGE

# Індекси значень (SensorData.java), 0 == value[0] == поле $3 у рядку журналу
NODE_ID, SEQNO, TIME_CPU, TIME_LPM, TIME_TX, TIME_LISTEN = 4, 5, 11, 12, 13, 14


def node_name(raw: int) -> str:
    """Rime-адреса -> ім'я вузла X.Y, як у Collect View (mapNodeID)."""
    return f"{raw & 0xff}.{(raw >> 8) & 0xff}"


def parse_log(path: Path) -> dict[str, list[list[int]]]:
    readings: dict[str, list[list[int]]] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        # формат: <time> ID:1 30 <29 значень>  -> рядок сенсорних даних
        if len(parts) < 3 or not parts[1].startswith("ID:") or parts[2] != "30":
            continue
        vals = [int(x) for x in parts[2:]]
        if len(vals) != 30:
            continue
        readings.setdefault(node_name(vals[NODE_ID]), []).append(vals)
    return readings


def power(vals: list[int]) -> dict[str, float]:
    cpu, lpm, tx, lst = vals[TIME_CPU], vals[TIME_LPM], vals[TIME_TX], vals[TIME_LISTEN]
    denom = cpu + lpm
    p_cpu = cpu * POWER_CPU / denom
    p_lpm = lpm * POWER_LPM / denom
    p_tx = tx * POWER_TRANSMIT / denom
    p_listen = lst * POWER_LISTEN / denom
    return {
        "cpu": p_cpu,
        "lpm": p_lpm,
        "tx": p_tx,
        "listen": p_listen,
        "total": p_cpu + p_lpm + p_tx + p_listen,
    }


def main() -> None:
    readings = parse_log(LOG)
    rows = []
    for name in sorted(readings, key=lambda s: tuple(map(int, s.split(".")))):
        last = readings[name][-1]  # кумулятивні тики -> беремо останній звіт
        p = power(last)
        rows.append({"node": name, "reports": len(readings[name]),
                     "seqno": last[SEQNO], **p})

    DATA.mkdir(exist_ok=True)
    (DATA / "power.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2))

    # ---- графік стовпців потужності ----
    plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 11})
    fig, ax = plt.subplots(figsize=(8.5, 4.4))
    names = [r["node"] for r in rows]
    xs = np.arange(len(rows))
    bottom = np.zeros(len(rows))
    for key, label, col in [("lpm", "LPM (сон)", "#bdc3c7"),
                            ("cpu", "CPU", "#1f4e79"),
                            ("listen", "Listen (прийом)", "#c0392b"),
                            ("tx", "Transmit (передача)", "#27ae60")]:
        vals = np.array([r[key] for r in rows])
        ax.bar(xs, vals, bottom=bottom, label=label, color=col)
        bottom += vals
    ax.set_xticks(xs, names)
    ax.set_xlabel("Вузол (Rime-адреса)")
    ax.set_ylabel("Середня потужність, мВт")
    ax.set_title("Споживана потужність вузлів-відправників (7 sender + 1 sink)")
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(alpha=0.3, axis="y")
    fig.tight_layout()
    ASSETS.mkdir(exist_ok=True)
    fig.savefig(ASSETS / "03-power.png", dpi=200)

    print(f"{'node':6} {'rep':>3} {'CPU':>6} {'LPM':>6} {'Listen':>7} {'TX':>6} {'Total':>7}")
    for r in rows:
        print(f"{r['node']:6} {r['reports']:3d} {r['cpu']:6.2f} {r['lpm']:6.2f} "
              f"{r['listen']:7.2f} {r['tx']:6.2f} {r['total']:7.2f}")


if __name__ == "__main__":
    main()
