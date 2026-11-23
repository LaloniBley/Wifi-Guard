#!/usr/bin/env bash
# ВМ2 «пользователь»: переключение между легитимной и подменной точкой доступа.
#
#   legit — маршрут к серверу напрямую через сеть host-only (легитимная ТД CORP-WIFI);
#   twin  — маршрут к серверу через ВМ нарушителя (подменная ТД во внутренней сети
#           «evil-twin»). Так моделируется итог шагов 3–4 сценария С1: клиента
#           отключили кадрами деаутентификации, и он автоматически подключился
#           к двойнику с тем же SSID;
#   status — через какой узел сейчас идёт трафик к серверу.
#
# SSH-подключение с Windows к ВМ (192.168.56.20) при переключении не рвётся:
# меняется только маршрут к серверу приложения.
# Использование: sudo ./wifi.sh legit|twin|status
set -euo pipefail
SERVER="${SERVER:-192.168.56.10}"
ROGUE="${ROGUE:-10.10.10.1}"
TWIN_IF="${TWIN_IF:-enp0s9}"

case "${1:-status}" in
  legit)
    ip route del "$SERVER/32" 2>/dev/null || true
    echo "Подключено к легитимной ТД"
    ;;
  twin)
    # клиент не должен принимать ICMP Redirect, иначе он «вернётся» на прямой маршрут
    sysctl -qw net.ipv4.conf.all.accept_redirects=0 "net.ipv4.conf.$TWIN_IF.accept_redirects=0"
    ip route replace "$SERVER/32" via "$ROGUE" dev "$TWIN_IF"
    echo "Подключено к подменной ТД нарушителя ($ROGUE)"
    ;;
  status) ;;
  *) echo "использование: sudo $0 legit|twin|status"; exit 1 ;;
esac
ip route get "$SERVER" | head -1
