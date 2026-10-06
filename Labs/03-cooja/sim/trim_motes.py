"""Залишити у .csc-файлі Cooja лише перші K вузлів (1 sink + решта sender).

Бере готовий приклад Contiki collect-tree-dense-noloss.csc і вирізає зайві
блоки <mote>...</mote>, лишаючи задану кількість. Решту файлу (типи мотів,
радіосередовище, плагіни, закриваючі теги) не змінює.

    python trim_motes.py SRC.csc DST.csc 8
"""
from __future__ import annotations

import re
import sys


def trim(src: str, keep: int) -> str:
    blocks = list(re.finditer(r"[ \t]*<mote>\s*<breakpoints.*?</mote>\n?", src, re.DOTALL))
    if len(blocks) < keep:
        raise SystemExit(f"у прикладі лише {len(blocks)} вузлів, треба {keep}")
    # Вирізаємо все від початку (keep+1)-го блоку до кінця останнього блоку.
    cut_start = blocks[keep].start()
    cut_end = blocks[-1].end()
    return src[:cut_start] + src[cut_end:]


def main() -> None:
    src_path, dst_path, keep = sys.argv[1], sys.argv[2], int(sys.argv[3])
    out = trim(open(src_path).read(), keep)
    open(dst_path, "w").write(out)
    n = out.count("<mote>")
    print(f"{dst_path}: {n} вузлів")


if __name__ == "__main__":
    main()
