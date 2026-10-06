"""Калькулятор CVSS v3.1 за специфікацією FIRST (розділ 7 і додаток A).

Рахує базову, часову та середовищну оцінки з рядка-вектора:

    >>> score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["base"]
    9.8
"""
from __future__ import annotations

import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}

BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x: float) -> float:
    """Округлення вгору до 0,1 без похибок плаваючої коми (додаток A)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity(s: float) -> str:
    if s == 0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"


def parse(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise ValueError("очікується префікс CVSS:3.1")
    m = dict(p.split(":") for p in parts[1:])
    missing = [k for k in BASE_KEYS if k not in m]
    if missing:
        raise ValueError(f"бракує базових метрик: {missing}")
    return m


def score(vector: str) -> dict[str, float | str]:
    m = parse(vector)
    g = lambda k, d="X": m.get(k, d)  # noqa: E731

    # ---- base ----
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (PR_C if changed else PR_U)[m["PR"]]
    expl = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + expl), 10))
    else:
        base = roundup(min(impact + expl, 10))

    # ---- temporal ----
    t_mult = E[g("E")] * RL[g("RL")] * RC[g("RC")]
    temporal = roundup(base * t_mult)

    # ---- environmental ----
    mod = lambda k: m[k] if g("M" + k) == "X" else m["M" + k]  # noqa: E731
    ms_changed = mod("S") == "C"
    miss = min(
        1
        - (1 - REQ[g("CR")] * CIA[mod("C")])
        * (1 - REQ[g("IR")] * CIA[mod("I")])
        * (1 - REQ[g("AR")] * CIA[mod("A")]),
        0.915,
    )
    if ms_changed:
        m_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
    else:
        m_impact = 6.42 * miss
    mpr = (PR_C if ms_changed else PR_U)[mod("PR")]
    m_expl = 8.22 * AV[mod("AV")] * AC[mod("AC")] * mpr * UI[mod("UI")]
    if m_impact <= 0:
        env = 0.0
    elif ms_changed:
        env = roundup(roundup(min(1.08 * (m_impact + m_expl), 10)) * t_mult)
    else:
        env = roundup(roundup(min(m_impact + m_expl, 10)) * t_mult)

    return {
        "base": base,
        "temporal": temporal,
        "environmental": env,
        "impact": round(impact, 2),
        "exploitability": round(expl, 2),
    }


if __name__ == "__main__":
    import doctest

    doctest.testmod(verbose=False)
    # Приклади зі специфікації FIRST «CVSS v3.1 Examples»
    for v, want in [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.4),  # приклад із методички, звірено з калькулятором FIRST
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # XSS, phpMyAdmin
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ]:
        got = score(v)["base"]
        assert got == want, (v, got, want)
    print("ok")
