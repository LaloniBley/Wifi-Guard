#!/usr/bin/env bash
# Публикация шлюза доступа на сетевом интерфейсе ВМ (сеть host-only VirtualBox).
# После запуска шлюз доступен с Windows и других ВМ: https://<IP ВМ>:8443
#
# Используется DNAT, а не kubectl port-forward: адрес источника клиента
# сохраняется, а TTL пакетов уменьшается на каждом маршрутизаторе, поэтому
# TTL-зонд видит реальное число транзитных узлов (признак N1).
#
# Использование: ./scripts/expose-gateway.sh [интерфейс] [порт]
#   по умолчанию: enp0s8 (второй адаптер VirtualBox, host-only), порт 8443
# Правила iptables не сохраняются после перезагрузки — запускайте скрипт заново.
set -euo pipefail
IFACE="${1:-enp0s8}"
PORT="${2:-8443}"
NODE="$(minikube -p wifi-guard ip)"
TARGET="$NODE:30443"

sudo sysctl -qw net.ipv4.ip_forward=1

# повторный запуск безопасен: сначала удаляем свои старые правила
sudo iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport "$PORT" \
  -j DNAT --to-destination "$TARGET" 2>/dev/null || true
sudo iptables -D DOCKER-USER -i "$IFACE" -p tcp -d "$NODE" --dport 30443 -j ACCEPT 2>/dev/null || true
sudo iptables -D DOCKER-USER -i "$IFACE" -d "$NODE" -j DROP 2>/dev/null || true

# 1) входящие на <IP ВМ>:8443 перенаправляются на NodePort шлюза в minikube
sudo iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport "$PORT" \
  -j DNAT --to-destination "$TARGET"
# 2) из внешней сети к узлу кластера пропускается только поток к шлюзу: остальные
#    порты узла (API Kubernetes, kubelet, SSH узла) закрыты, даже если нарушитель
#    направит трафик в сеть кластера через эту ВМ (испытание Э12 главы 4).
#    Правила вставляются в начало цепочки, поэтому ACCEPT добавляется последним.
sudo iptables -I DOCKER-USER -i "$IFACE" -d "$NODE" -j DROP
sudo iptables -I DOCKER-USER -i "$IFACE" -p tcp -d "$NODE" --dport 30443 -j ACCEPT

IP="$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1)"
echo "Шлюз опубликован: https://$IP:$PORT  ->  https://$TARGET"
