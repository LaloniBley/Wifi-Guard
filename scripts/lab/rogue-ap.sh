#!/usr/bin/env bash
# ВМ1 «нарушитель»: подменная точка доступа («злой двойник») для испытаний главы 4.
#
# Внутренняя сеть VirtualBox «evil-twin» играет роль радиоканала подменной ТД:
# клиент, переключённый на неё, выходит к приложению через ВМ нарушителя.
# Как и настоящая подменная ТД (hostapd + NAT), ВМ пересылает трафик клиента
# дальше в сеть с трансляцией адресов, т. е. является дополнительным
# маршрутизатором на пути «клиент — сервер»: TTL пакетов уменьшается на 1,
# что выявляет индикатор N1 (HOPS_DEVIATION).
#
# Использование: sudo ./rogue-ap.sh start|stop|status
#   UPLINK — интерфейс в сторону сервера (host-only), по умолчанию enp0s8;
#   TWIN   — интерфейс «эфира» подменной ТД (внутренняя сеть), по умолчанию enp0s9.
set -euo pipefail
UPLINK="${UPLINK:-enp0s8}"
TWIN="${TWIN:-enp0s9}"
NET="${NET:-10.10.10.0/24}"

rules() {   # $1 = -A (добавить) или -D (удалить)
  iptables -t nat "$1" POSTROUTING -s "$NET" -o "$UPLINK" -j MASQUERADE
  iptables "$1" FORWARD -i "$TWIN" -o "$UPLINK" -s "$NET" -j ACCEPT
  iptables "$1" FORWARD -i "$UPLINK" -o "$TWIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

case "${1:-status}" in
  start)
    sysctl -qw net.ipv4.ip_forward=1
    # ICMP Redirect подсказал бы клиенту прямой маршрут в обход нарушителя
    sysctl -qw net.ipv4.conf.all.send_redirects=0 "net.ipv4.conf.$TWIN.send_redirects=0"
    rules -D 2>/dev/null || true
    rules -A
    echo "Подменная ТД запущена: клиенты сети $NET выходят к серверу через $UPLINK (NAT)"
    ;;
  stop)
    rules -D 2>/dev/null || true
    sysctl -qw net.ipv4.ip_forward=0
    echo "Подменная ТД остановлена"
    ;;
  status)
    echo "ip_forward = $(sysctl -n net.ipv4.ip_forward)"
    iptables -t nat -L POSTROUTING -v -n | grep -E "MASQUERADE|pkts" || true
    ;;
  *) echo "использование: sudo $0 start|stop|status"; exit 1 ;;
esac
