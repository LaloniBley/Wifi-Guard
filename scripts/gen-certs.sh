#!/usr/bin/env bash
# Выпуск учебной PKI: корневой УЦ, сертификат сервера (шлюза) и сертификаты
# устройств пользователей. Ключи ECDSA P-256 (эквивалент RSA-3072 по стойкости).
# Использование: ./scripts/gen-certs.sh [IP узла minikube] [доп. IP через запятую]
#   пример для ВМ VirtualBox: ./scripts/gen-certs.sh 192.168.49.2 192.168.56.10
set -euo pipefail
cd "$(dirname "$0")/.."
NODE_IP="${1:-192.168.49.2}"
EXTRA_IPS="${2:-}"   # адреса, по которым шлюз доступен снаружи (например, IP ВМ)
SAN="DNS:wifi-guard.local,DNS:localhost,IP:127.0.0.1,IP:$NODE_IP"
for ip in ${EXTRA_IPS//,/ }; do SAN="$SAN,IP:$ip"; done
OUT=certs
DAYS_CA=730       # 2 года — срок учебного УЦ
DAYS_LEAF=365     # 1 год — срок сертификатов сервера и устройств
mkdir -p "$OUT"

if [[ ! -f $OUT/ca.key ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out $OUT/ca.key
  openssl req -x509 -new -key $OUT/ca.key -sha256 -days $DAYS_CA \
    -subj "/O=WiFi-Guard/CN=WiFi-Guard Device CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -out $OUT/ca.crt
fi

issue() {  # issue <имя> <subject> <расширения>
  local name=$1 subj=$2 ext=$3
  openssl ecparam -name prime256v1 -genkey -noout -out $OUT/$name.key
  openssl req -new -key $OUT/$name.key -subj "$subj" -out $OUT/$name.csr
  openssl x509 -req -in $OUT/$name.csr -CA $OUT/ca.crt -CAkey $OUT/ca.key \
    -CAcreateserial -days $DAYS_LEAF -sha256 -extfile <(printf "%s" "$ext") -out $OUT/$name.crt
  rm -f $OUT/$name.csr
}

# расширения по RFC 5280 — их требует строгая проверка цепочки (Python 3.13+, браузеры)
CLIENT_EXT="keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
authorityKeyIdentifier=keyid"

issue server "/O=WiFi-Guard/CN=wifi-guard.local" \
  "subjectAltName=$SAN
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid"
issue user1    "/O=WiFi-Guard/CN=device-ivanov"   "$CLIENT_EXT"
issue admin1   "/O=WiFi-Guard/CN=device-admin"    "$CLIENT_EXT"
# устройство нарушителя с сертификатом того же УЦ (скомпрометированное устройство
# другого сотрудника) — нужно для демонстрации сценария С2 «перехват токена»
issue attacker "/O=WiFi-Guard/CN=device-petrov"   "$CLIENT_EXT"

# PKCS#12 для импорта в Postman/браузер (пароль: wifiguard)
for n in user1 admin1 attacker; do
  openssl pkcs12 -export -in $OUT/$n.crt -inkey $OUT/$n.key -certfile $OUT/ca.crt \
    -passout pass:wifiguard -out $OUT/$n.p12
done
echo "Сертификаты созданы в каталоге $OUT/"
