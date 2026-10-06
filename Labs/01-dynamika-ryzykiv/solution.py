"""ЛР1, варіант 3: лінійна регресія кількості зареєстрованих атак за місяцями.

Формули (1)-(9) методички рахуються вручну; np.polyfit лише звіряє результат.
Запуск з кореня теки роботи:  ../../.venv/bin/python solution.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DATA = HERE / "data"

# Варіант 3: x : місяць від початку дії політики, y : кількість зареєстрованих атак
x = np.arange(1, 13, dtype=float)
y = np.array([6, 5, 11, 13, 15, 20, 24, 25, 24, 26, 28, 19], dtype=float)
n = len(x)

# (3), (4) середні
x_mean = x.sum() / n
y_mean = y.sum() / n
# (5) дисперсія x, (6) коваріація; знаменник n-1, як у методичці
var_x = ((x - x_mean) ** 2).sum() / (n - 1)
cov_xy = ((x - x_mean) * (y - y_mean)).sum() / (n - 1)
# (1), (2) параметри регресії МНК
a = cov_xy / var_x
b = y_mean - a * x_mean
# (9) модельні значення
y_hat = a * x + b
# (7) коефіцієнт детермінації
r2 = ((y_hat - y_mean) ** 2).sum() / ((y - y_mean) ** 2).sum()
# (8) середня відносна похибка апроксимації, %
eps = np.abs((y - y_hat) / y).sum() / n * 100

# Звірка з бібліотечним МНК
a_np, b_np = np.polyfit(x, y, 1)
assert np.isclose(a, a_np) and np.isclose(b, b_np)

# Додатково: значущість нахилу (t-критерій), кореляція Пірсона
var_y = ((y - y_mean) ** 2).sum() / (n - 1)
r = cov_xy / np.sqrt(var_x * var_y)
resid = y - y_hat
s_e = np.sqrt((resid**2).sum() / (n - 2))  # стандартна похибка регресії
se_a = s_e / np.sqrt(((x - x_mean) ** 2).sum())
t_a = a / se_a
T_CRIT = 2.228  # t(0.975; df=10)

# Прогноз на наступний квартал за умови незмінної політики
x_fc = np.array([13, 14, 15], dtype=float)
y_fc = a * x_fc + b

# Перше і друге півріччя окремо: чи сповільнюється зростання
def fit(xs: np.ndarray, ys: np.ndarray) -> tuple[float, float]:
    k, c = np.polyfit(xs, ys, 1)
    return float(k), float(c)

a_h1, _ = fit(x[:6], y[:6])
a_h2, _ = fit(x[6:], y[6:])

# Порівняльна квадратична модель: чи краще вона описує насичення
q = np.polyfit(x, y, 2)
y_q = np.polyval(q, x)
r2_q = 1 - ((y - y_q) ** 2).sum() / ((y - y_mean) ** 2).sum()
eps_q = np.abs((y - y_q) / y).sum() / n * 100
x_peak_q = -q[1] / (2 * q[0])

results = {
    "n": n,
    "x_mean": x_mean,
    "y_mean": y_mean,
    "var_x": var_x,
    "var_y": var_y,
    "cov_xy": cov_xy,
    "a": a,
    "b": b,
    "r2": r2,
    "eps_pct": eps,
    "r": r,
    "s_e": s_e,
    "se_a": se_a,
    "t_a": t_a,
    "t_crit": T_CRIT,
    "forecast": dict(zip([int(v) for v in x_fc], [float(v) for v in y_fc])),
    "a_h1": a_h1,
    "a_h2": a_h2,
    "y_sum_h1": float(y[:6].sum()),
    "y_sum_h2": float(y[6:].sum()),
    "quad": [float(c) for c in q],
    "r2_quad": float(r2_q),
    "eps_quad_pct": float(eps_q),
    "x_peak_quad": float(x_peak_q),
}

DATA.mkdir(exist_ok=True)
ASSETS.mkdir(exist_ok=True)
(DATA / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))

with open(DATA / "table.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["x", "y", "x-x_mean", "y-y_mean", "(x-x_mean)^2", "(x-x_mean)(y-y_mean)",
                "y_hat", "(y_hat-y_mean)^2", "(y-y_mean)^2", "|y-y_hat|/y"])
    for xi, yi, yh in zip(x, y, y_hat):
        dx, dy = xi - x_mean, yi - y_mean
        w.writerow([int(xi), int(yi), f"{dx:.1f}", f"{dy:.2f}", f"{dx*dx:.2f}", f"{dx*dy:.2f}",
                    f"{yh:.2f}", f"{(yh-y_mean)**2:.2f}", f"{dy*dy:.2f}", f"{abs(yi-yh)/yi:.4f}"])

# ---- рисунки ----
plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 12})

fig, ax = plt.subplots(figsize=(8, 4.8))
ax.scatter(x, y, color="#1f4e79", zorder=3, label="Спостереження")
xx = np.linspace(1, 15, 100)
ax.plot(xx[xx <= 12], a * xx[xx <= 12] + b, color="#c0392b",
        label=f"Регресія  y = {a:.3f}x + {b:.3f}")
ax.plot(xx[xx >= 12], a * xx[xx >= 12] + b, color="#c0392b", ls="--",
        label="Прогноз на місяці 13...15")
for xi, yi, yh in zip(x, y, y_hat):
    ax.plot([xi, xi], [yi, yh], color="grey", lw=0.8, zorder=1)
xq = np.linspace(1, 12, 100)
ax.plot(xq, np.polyval(q, xq), color="#7f8c8d", ls=":", lw=1.5,
        label=f"Квадратична модель (R² = {r2_q:.3f})")
ax.set_xlabel("Місяць від початку дії політики безпеки, x")
ax.set_ylabel("Кількість зареєстрованих атак, y")
ax.set_xticks(range(1, 16))
ax.grid(alpha=0.3)
ax.legend(loc="upper left")
ax.text(0.98, 0.04, f"$R^2$ = {r2:.3f}\nε = {eps:.1f} %", transform=ax.transAxes,
        ha="right", va="bottom", bbox=dict(fc="white", ec="grey", alpha=0.9))
fig.tight_layout()
fig.savefig(ASSETS / "01-regression.png", dpi=200)

fig, ax = plt.subplots(figsize=(8, 3.2))
ax.bar(x, resid, color=np.where(resid >= 0, "#1f4e79", "#c0392b"))
ax.axhline(0, color="black", lw=0.8)
ax.set_xlabel("Місяць, x")
ax.set_ylabel("Залишок y − y*")
ax.set_xticks(range(1, 13))
ax.grid(alpha=0.3, axis="y")
fig.tight_layout()
fig.savefig(ASSETS / "02-residuals.png", dpi=200)

for k, v in results.items():
    print(f"{k:10s} {v}")
