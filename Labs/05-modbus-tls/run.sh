#!/usr/bin/env bash
# Відтворити обидва сценарії й зібрати перехоплений трафік.
#   до захисту:   клієнт -> сніфер -> сервер (відкритий Modbus)
#   після захисту: те саме через TLS
set -euo pipefail
cd "$(dirname "$0")"

gcc -O2 -Wall -Wextra -o modbus_tcp src/modbus_tcp.c -lssl -lcrypto
[ -f certs/server.crt ] || bash gen-certs.sh
mkdir -p data
PY=../../.venv/bin/python

run_case() {
  local name=$1 tls=$2
  ./modbus_tcp --server $tls --port 1502 >/dev/null 2>&1 & SRV=$!
  sleep 0.5
  $PY src/sniffer.py --listen 1600 --server 1502 --out "data/sniff-$name.txt" & SNF=$!
  sleep 0.5
  ./modbus_tcp --client $tls --port 1600 --count 4 >"data/client-$name.txt" 2>&1
  sleep 0.3
  kill $SNF $SRV 2>/dev/null || true
  wait $SNF 2>/dev/null || true
  echo "== $name: $(wc -l < data/sniff-$name.txt) рядків дампу"
}

run_case plain ""
run_case tls "--tls"
echo "готово: data/sniff-plain.txt, data/sniff-tls.txt"
