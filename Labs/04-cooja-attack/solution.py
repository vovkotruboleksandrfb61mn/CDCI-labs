"""ЛР4: порівняння споживання енергії до та після DIS-атаки на RPL.

Обробляє два журнали Cooja: baseline (7 sender + 1 sink) і attack (той самий
сценарій + шкідливий вузол, що безперервно розсилає DIS). Рахує потужність
кожного легітимного вузла за energest-лічильниками (формули Collect View) і
будує порівняння до/після для Power, Listen Power, CPU Power.

    ../../.venv/bin/python solution.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DATA = HERE / "data"

VOLTAGE = 3.0
POWER_CPU = 1.800 * VOLTAGE
POWER_LPM = 0.0545 * VOLTAGE
POWER_TRANSMIT = 17.7 * VOLTAGE
POWER_LISTEN = 20.0 * VOLTAGE
NODE_ID, TIME_CPU, TIME_LPM, TIME_TX, TIME_LISTEN = 4, 11, 12, 13, 14


def node_name(raw: int) -> str:
    return f"{raw & 0xff}.{(raw >> 8) & 0xff}"


def parse_log(path: Path) -> dict[str, list[list[int]]]:
    readings: dict[str, list[list[int]]] = {}
    for line in path.read_text().splitlines():
        p = line.split()
        if len(p) < 3 or not p[1].startswith("ID:") or p[2] != "30":
            continue
        vals = [int(x) for x in p[2:]]
        if len(vals) == 30:
            readings.setdefault(node_name(vals[NODE_ID]), []).append(vals)
    return readings


def power(vals: list[int]) -> dict[str, float]:
    cpu, lpm, tx, lst = vals[TIME_CPU], vals[TIME_LPM], vals[TIME_TX], vals[TIME_LISTEN]
    d = cpu + lpm
    pc, pl, pt, pls = (cpu * POWER_CPU / d, lpm * POWER_LPM / d,
                       tx * POWER_TRANSMIT / d, lst * POWER_LISTEN / d)
    return {"cpu": pc, "lpm": pl, "tx": pt, "listen": pls, "total": pc + pl + pt + pls}


def avg_power(readings: dict[str, list[list[int]]], nodes: list[str]) -> dict[str, dict]:
    out = {}
    for n in nodes:
        # усереднюємо потужність по всіх звітах вузла (energest кумулятивний у вікні звіту)
        ps = [power(v) for v in readings[n]]
        out[n] = {k: float(np.mean([p[k] for p in ps])) for k in ps[0]}
    return out


def main() -> None:
    base = parse_log(DATA / "lab3-baseline.log")
    atk = parse_log(DATA / "lab4-attack.log")
    # легітимні вузли-відправники: ті, що є в обох запусках (2.2 ... 8.8)
    legit = sorted(set(base) & set(atk),
                   key=lambda s: tuple(map(int, s.split("."))))
    attacker = sorted(set(atk) - set(base))  # 9.9

    pb = avg_power(base, legit)
    pa = avg_power(atk, legit)

    rows = []
    for n in legit:
        rows.append({
            "node": n,
            "total_before": pb[n]["total"], "total_after": pa[n]["total"],
            "listen_before": pb[n]["listen"], "listen_after": pa[n]["listen"],
            "cpu_before": pb[n]["cpu"], "cpu_after": pa[n]["cpu"],
            "total_delta_pct": 100 * (pa[n]["total"] - pb[n]["total"]) / pb[n]["total"],
        })

    summary = {
        "legit_nodes": legit,
        "attacker": attacker,
        "mean_total_before": float(np.mean([r["total_before"] for r in rows])),
        "mean_total_after": float(np.mean([r["total_after"] for r in rows])),
        "mean_listen_before": float(np.mean([r["listen_before"] for r in rows])),
        "mean_listen_after": float(np.mean([r["listen_after"] for r in rows])),
        "mean_cpu_before": float(np.mean([r["cpu_before"] for r in rows])),
        "mean_cpu_after": float(np.mean([r["cpu_after"] for r in rows])),
        "rows": rows,
    }
    (DATA / "compare.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))

    # ---- графік: до/після для Total, Listen, CPU ----
    plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 11})
    fig, axes = plt.subplots(1, 3, figsize=(12, 4.3), sharey=False)
    names = [r["node"] for r in rows]
    xs = np.arange(len(rows))
    w = 0.38
    for ax, (key, title) in zip(axes, [("total", "Повна потужність"),
                                       ("listen", "Listen Power"),
                                       ("cpu", "CPU Power")]):
        b = [pb[n][key] for n in names]
        a = [pa[n][key] for n in names]
        ax.bar(xs - w / 2, b, w, label="до атаки", color="#1f4e79")
        ax.bar(xs + w / 2, a, w, label="після атаки", color="#c0392b")
        ax.set_title(title + ", мВт")
        ax.set_xticks(xs, names, fontsize=8, rotation=45)
        ax.grid(alpha=0.3, axis="y")
    axes[0].legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    ASSETS.mkdir(exist_ok=True)
    fig.savefig(ASSETS / "03-power-compare.png", dpi=200)

    print(f"legit nodes: {legit}")
    print(f"attacker: {attacker}")
    print(f"{'node':6} {'tot_bef':>8} {'tot_aft':>8} {'Δ%':>7} {'lst_bef':>8} {'lst_aft':>8} {'cpu_bef':>8} {'cpu_aft':>8}")
    for r in rows:
        print(f"{r['node']:6} {r['total_before']:8.3f} {r['total_after']:8.3f} "
              f"{r['total_delta_pct']:7.1f} {r['listen_before']:8.3f} {r['listen_after']:8.3f} "
              f"{r['cpu_before']:8.3f} {r['cpu_after']:8.3f}")
    print(f"MEAN   {summary['mean_total_before']:8.3f} {summary['mean_total_after']:8.3f}"
          f"   listen {summary['mean_listen_before']:.3f}->{summary['mean_listen_after']:.3f}"
          f"   cpu {summary['mean_cpu_before']:.3f}->{summary['mean_cpu_after']:.3f}")


if __name__ == "__main__":
    main()
