#!/usr/bin/env bash
# Відтворити всі сценарії й зібрати перехоплений трафік.
#   до захисту:   клієнт -> сніфер -> сервер (відкритий Modbus)
#   після захисту: те саме через TLS
#   атаки: підміна байта (--flip), повторне відтворення (--replay),
#          підробний сервер (сертифікат не від нашого CA)
#   продуктивність: --bench (час з'єднання та запит-відповідь)
set -euo pipefail
cd "$(dirname "$0")"

gcc -O2 -Wall -Wextra -o modbus_tcp src/modbus_tcp.c -lssl -lcrypto
mkdir -p certs data
[ -f certs/server.crt ] || bash gen-certs.sh
mkdir -p data
PY=python3

run_case() {  # name tls [sniffer args...] [client args: --hold N / --repeat N]
  local name=$1 tls=$2; shift 2
  local sn_args=() cl_args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --hold|--repeat) cl_args+=("$1" "$2"); shift 2;;
      *) sn_args+=("$1"); shift;;
    esac
  done
  ./modbus_tcp --server $tls --port 1502 >/dev/null 2>&1 & SRV=$!
  sleep 0.5
  $PY src/sniffer.py --listen 1600 --server 1502 --out "data/sniff-$name.txt" \
      "${sn_args[@]}" & SNF=$!
  sleep 0.5
  ./modbus_tcp --client $tls --port 1600 "${cl_args[@]}" >"data/client-$name.txt" 2>&1 || true
  sleep 0.3
  kill $SNF $SRV 2>/dev/null || true
  wait $SNF 2>/dev/null || true
  echo "== $name: $(wc -l < data/sniff-$name.txt) рядків дампу"
}

# базове спостереження (пассивний сніфер)
run_case plain ""
run_case tls "--tls"

# атака 1: підміна команди (байт початкової адреси у запиті клієнта)
run_case plain-flip "" --flip
run_case tls-flip "--tls" --flip

# атака 2: повторне відтворення перехопленого запиту (клієнт тримає з'єднання)
run_case plain-replay "" --replay --hold 700
run_case tls-replay "--tls" --replay --hold 700

# атака 3: підробний сервер із сертифікатом не від нашого CA
if [ ! -f certs/evil.key ] || [ ! -f certs/evil.crt ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out certs/evil.key
  openssl req -x509 -new -key certs/evil.key -sha256 -days 365 -out certs/evil.crt \
      -subj "/C=UA/O=Evil/CN=plc.local"
fi
./modbus_tcp --server --tls --port 1502 --cert certs/evil.crt --key certs/evil.key \
    >/dev/null 2>&1 & SRV=$!
sleep 0.5
./modbus_tcp --client --tls --port 1502 >data/client-evil-server.txt 2>&1 || true
kill $SRV 2>/dev/null || true
echo "== evil-server: клієнт відмовився: $(tail -1 data/client-evil-server.txt)"

# продуктивність: 200 з'єднань, по 20 запитів
./modbus_tcp --server --port 1502 >/dev/null 2>&1 & S1=$!
./modbus_tcp --server --tls --port 1503 >/dev/null 2>&1 & S2=$!
sleep 0.5
{
  echo "== plain"
  ./modbus_tcp --bench 200 --port 1502
  echo "== TLS 1.3"
  ./modbus_tcp --bench 200 --tls --port 1503
} > data/bench.txt 2>&1
kill $S1 $S2 2>/dev/null || true
echo "готово: data/sniff-*.txt, data/client-*.txt, data/bench.txt"
