"""ЛР2, варіант 4: експлуатація вразливостей ПЗ і прошивок кінцевих пристроїв ІІоТ.

Для п'яти реальних CVE рахується CVSS v3.1: базова оцінка (вектор NVD), часова
(зрілість експлойта, наявність виправлення) і середовищна для умовного ОКІ,
міського водоканалу, у двох станах: «як є» і після компенсуючих заходів.

    ../../.venv/bin/python solution.py            # розрахунки й графік
    ../../.venv/bin/python solution.py --first    # + знімки й звірка з калькулятором FIRST
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from cvss31 import score, severity

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DATA = HERE / "data"
FIRST_URL = "https://www.first.org/cvss/calculator/3.1#"

# base: первинний вектор NVD; temporal: E/RL/RC; env_now: вимоги CR/IR/AR активу;
# env_after: модифіковані метрики після компенсуючих заходів (поки патч не встановлено).
CASES = [
    {
        "id": "CVE-2020-11896",
        "short": "Ripple20, стек Treck",
        "asset": "мережеві карти ДБЖ, шлюзи RS-485/Ethernet",
        "base": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "temporal": "E:P/RL:O/RC:C",
        "env_now": "CR:L/IR:H/AR:H",
        "env_after": "MAV:A",
    },
    {
        "id": "CVE-2021-36260",
        "short": "Hikvision, ін'єкція команд",
        "asset": "IP-камери охорони периметра",
        "base": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "temporal": "E:H/RL:O/RC:C",
        "env_now": "CR:H/IR:M/AR:M",
        "env_after": "MAV:A",
    },
    {
        "id": "CVE-2022-38465",
        "short": "SIMATIC S7-1200/1500, ключ",
        "asset": "ПЛК керування насосами",
        "base": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "temporal": "E:P/RL:O/RC:C",
        "env_now": "CR:H/IR:H/AR:H",
        "env_after": "MPR:H",
    },
    {
        "id": "CVE-2019-10953",
        "short": "ПЛК, DoS-флуд",
        "asset": "ПЛК (ABB, Phoenix, Schneider, Siemens, WAGO)",
        "base": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "temporal": "E:H/RL:W/RC:C",
        "env_now": "CR:L/IR:M/AR:H",
        "env_after": "MAV:A",
    },
    {
        "id": "CVE-2019-16336",
        "short": "SweynTooth, BLE PSoC 4",
        "asset": "бездротові BLE-датчики тиску й рівня",
        "base": "AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "temporal": "E:F/RL:O/RC:C",
        "env_now": "CR:L/IR:L/AR:M",
        "env_after": "MAC:H",
    },
]


def vectors(c: dict) -> dict[str, str]:
    b = "CVSS:3.1/" + c["base"]
    t = f"{b}/{c['temporal']}"
    now = f"{t}/{c['env_now']}"
    after = f"{now}/{c['env_after']}"
    return {"base": b, "temporal": t, "env_now": now, "env_after": after}


def nvd_record(cve: str) -> dict:
    d = json.loads((DATA / f"{cve}.json").read_text())
    v = d["vulnerabilities"][0]["cve"]
    metrics = v["metrics"]["cvssMetricV31"]
    return {
        "published": v["published"][:10],
        "kev": bool(v.get("cisaExploitAdd")),
        "cwe": sorted({w["description"][0]["value"] for w in v.get("weaknesses", [])}),
        "metrics": [(m["source"], m["type"], m["cvssData"]["vectorString"],
                     m["cvssData"]["baseScore"]) for m in metrics],
    }


def first_scores(vector: str) -> dict[str, float]:
    """Оцінки, які показує офіційний калькулятор FIRST для цього вектора."""
    dom = subprocess.run(
        ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu",
         "--virtual-time-budget=15000", "--dump-dom", FIRST_URL + vector],
        capture_output=True, text=True, timeout=90).stdout
    out = {}
    for k in ("base", "temporal", "environmental"):
        m = re.search(rf'id="{k}MetricScore">([\d.]+)<', dom)
        out[k] = float(m.group(1)) if m else float("nan")
    return out


def first_screenshot(vector: str, png: Path) -> None:
    from PIL import Image

    raw = png.with_suffix(".raw.png")
    subprocess.run(
        ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
         "--window-size=1280,1600", "--virtual-time-budget=15000",
         f"--screenshot={raw}", FIRST_URL + vector],
        capture_output=True, timeout=90, check=True)
    # базові метрики, рядок-вектор, часові метрики й заголовок середовищної оцінки
    im = Image.open(raw)
    top = im.crop((250, 375, 1270, 1290))
    env = im.crop((250, 1336, 1270, 1397))
    out = Image.new("RGB", (top.width, top.height + env.height), "white")
    out.paste(top, (0, 0))
    out.paste(env, (0, top.height))
    out.save(png)
    raw.unlink()


def main() -> None:
    with_first = "--first" in sys.argv
    rows = []
    for c in CASES:
        v = vectors(c)
        s_b = score(v["base"])
        s_now = score(v["env_now"])
        s_after = score(v["env_after"])
        nvd = nvd_record(c["id"])
        primary = next(m for m in nvd["metrics"] if m[1] == "Primary")
        assert primary[2] == v["base"], (c["id"], primary[2])
        assert primary[3] == s_b["base"], (c["id"], primary[3], s_b["base"])
        row = {
            **c,
            "vectors": v,
            "nvd": nvd,
            "impact": s_b["impact"],
            "exploitability": s_b["exploitability"],
            "base": s_b["base"],
            "temporal": s_now["temporal"],
            "env_now": s_now["environmental"],
            "env_after": s_after["environmental"],
            "sev_base": severity(s_b["base"]),
            "sev_now": severity(s_now["environmental"]),
            "sev_after": severity(s_after["environmental"]),
        }
        if with_first:
            f_now, f_after = first_scores(v["env_now"]), first_scores(v["env_after"])
            row["first"] = {"env_now": f_now, "env_after": f_after}
            assert f_now == {"base": row["base"], "temporal": row["temporal"],
                             "environmental": row["env_now"]}, (c["id"], f_now)
            assert f_after["environmental"] == row["env_after"], (c["id"], f_after)
            first_screenshot(v["env_now"], ASSETS / f"first-{c['id']}.png")
        rows.append(row)

    # Інші оцінки тих самих CVE (вендор як CNA), якщо відрізняються від NVD
    for r in rows:
        for src, typ, vec, sc in r["nvd"]["metrics"]:
            if typ == "Secondary" and vec != r["vectors"]["base"]:
                r["alt"] = {"source": src, "vector": vec, "score": sc}

    DATA.mkdir(exist_ok=True)
    (DATA / "results.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2))

    # ---- графік ----
    plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 11})
    fig, ax = plt.subplots(figsize=(9, 4.6))
    labels = [f"{r['id']}\n{r['short']}" for r in rows]
    series = [("Базова", "base", "#1f4e79"), ("Часова", "temporal", "#5b8db8"),
              ("Середовищна, як є", "env_now", "#c0392b"),
              ("Після заходів", "env_after", "#27ae60")]
    xs = np.arange(len(rows))
    w = 0.2
    for k, (name, key, col) in enumerate(series):
        vals = [r[key] for r in rows]
        bars = ax.bar(xs + (k - 1.5) * w, vals, w, label=name, color=col)
        ax.bar_label(bars, fmt="%.1f", fontsize=8, padding=1)
    for lo, hi, col in [(0, 4, "#eafaf1"), (4, 7, "#fef9e7"), (7, 9, "#fdf2e9"), (9, 10.6, "#fdedec")]:
        ax.axhspan(lo, hi, color=col, zorder=0)
    for y0, name in [(2, "Low"), (5.5, "Medium"), (8, "High"), (9.6, "Critical")]:
        ax.text(len(rows) - 0.45, y0, name, ha="right", va="center", fontsize=8, color="grey")
    ax.set_xticks(xs, labels, fontsize=8.5)
    ax.set_ylim(0, 10.6)
    ax.set_ylabel("Оцінка CVSS v3.1")
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.2), frameon=False)
    fig.tight_layout()
    ASSETS.mkdir(exist_ok=True)
    fig.savefig(ASSETS / "01-scores.png", dpi=200)

    for r in rows:
        print(f"{r['id']}  base {r['base']:4} ({r['sev_base']:8}) temporal {r['temporal']:4} "
              f"env {r['env_now']:4} ({r['sev_now']:8}) after {r['env_after']:4} ({r['sev_after']})"
              + ("  FIRST ok" if "first" in r else ""))
        print("   ", r["vectors"]["env_after"])


if __name__ == "__main__":
    main()
