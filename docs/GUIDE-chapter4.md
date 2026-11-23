# Методичка к главе 4: испытательный стенд, тестирование и мониторинг

Продолжение методички `GUIDE-VirtualBox.md`. Паттерн уже развёрнут на ВМ `wg-server` (глава 3).
Здесь мы добавим две лёгкие ВМ, нарушителя и пользователя, прогоним серии атак и снимем метрики
в Prometheus и Grafana. Результаты нужны для текста главы 4.

**Время:** 2–2,5 часа, из них около 40 минут — установка Ubuntu на новую ВМ.

```
                   Windows (ноутбук) 192.168.56.1 — браузер: Grafana, Prometheus
                                   │
 ══════════ сеть host-only 192.168.56.0/24 («легитимная ТД CORP-WIFI») ══════════
      │                          │                                │
 ВМ3 wg-server .10          ВМ2 wg-user .20                  ВМ1 wg-attacker .30
 кластер minikube           клиент «Корпоративного           подменная ТД (NAT),
 шлюз :8443                 портала»: client_sim,            перехват токена,
 Prometheus, Grafana        experiment, pytest               перебор паролей, nmap
                                 │ 10.10.10.20                    │ 10.10.10.1
                                 └══ внутренняя сеть «evil-twin» ═┘
                                     («эфир» подменной ТД)
```

| ВМ | Роль по ТЗ | ОЗУ | Адаптеры |
|---|---|---|---|
| ВМ3 `wg-server` | сеть и кластер | как была | NAT, host-only |
| ВМ2 `wg-user` | пользователь | 1 ГБ | NAT, host-only, внутренняя сеть `evil-twin` |
| ВМ1 `wg-attacker` | нарушитель | 1 ГБ | NAT, host-only, внутренняя сеть `evil-twin` |

**Как моделируется атака С1.** Радиоканал внутри VirtualBox недоступен, поэтому «подключение к Wi-Fi» разделено
на две части:
* **сетевая часть — настоящая.** Когда ВМ2 переключается на подменную ТД, её трафик к серверу действительно идёт
  через ВМ нарушителя, как через настоящую подменную ТД с NAT. TTL пакетов уменьшается на единицу, и TTL-зонд в
  кластере видит лишний транзитный узел. Это индикатор N1;
* **радиочасть — телеметрия.** Что «видит» Wi-Fi-адаптер клиента (BSSID, PMF, соседние сети), передаёт
  `experiment.py` в заголовке телеметрии по сценарию. Это индикаторы K1, K2 и N2.

Как и в первой методичке: **одна команда — один блок**. Блоки с пометкой «ВМ1», «ВМ2», «ВМ3» выполняются в SSH-окне
соответствующей ВМ. Удобно держать три окна PowerShell, по одному на ВМ.

---

## 1. Обновить проект на ВМ3

1. Скопируй новый архив в ВМ3. **PowerShell:**
   ```powershell
   scp "C:\Users\noize\Desktop\3 курс\Курсовая\wifi-guard.zip" laloni@192.168.56.10:~
   ```
2. Распакуй поверх старого проекта. Сертификаты, секреты и `.venv` в архив не входят и останутся на месте. **ВМ3:**
   ```bash
   cd ~ && unzip -o wifi-guard.zip && cd ~/wifi-guard && chmod +x scripts/*.sh scripts/lab/*.sh
   ```
3. Убедись, что кластер работает:
   ```bash
   minikube status -p wifi-guard | head -3
   ```
   Если `Stopped`, запусти кластер и подожди готовности подов (как в разделе 15 первой методички).
4. Проверь код. Должно быть `37 passed` и покрытие около 85 %:
   ```bash
   pip install pytest-cov==6.1.1 && pytest -q --cov=common --cov=services --cov-report=term
   ```
   📸 **Скриншот 4.1:** таблица покрытия и `37 passed`.
5. Примени изменения: дашборд Grafana, правила Prometheus и новый образ аудита.
   ```bash
   cd ~/wifi-guard/ansible && ansible-playbook -i inventory.ini deploy.yml
   ```
   ```bash
   kubectl -n wg-monitoring rollout restart deployment/audit && kubectl -n wg-monitoring rollout status deployment/audit
   ```
6. Опубликуй шлюз (после каждой перезагрузки ВМ3):
   ```bash
   cd ~/wifi-guard && ./scripts/expose-gateway.sh
   ```
7. Отправь изменения на GitHub:
   ```bash
   cd ~/wifi-guard && git add . && git commit -m "Глава 4: дашборд Grafana, правила Prometheus, испытания" && git push
   ```
   На вкладке Actions в задании `manifests` появится шаг `promtool` с тестами правил оповещения.

---

## 2. Grafana и Prometheus в браузере

Нужны два отдельных окна SSH к ВМ3: проброс порта занимает окно. Пароль Grafana:

```bash
cat ~/wifi-guard/ansible/.secrets/grafana; echo
```

**Окно A (ВМ3)**, Grafana:
```bash
kubectl -n wg-monitoring port-forward --address 0.0.0.0 svc/grafana 3000:3000
```

**Окно B (ВМ3)**, Prometheus:
```bash
kubectl -n wg-monitoring port-forward --address 0.0.0.0 svc/prometheus 9090:9090
```

В браузере на Windows:
* `http://192.168.56.10:3000` → логин `admin` → сразу откроется дашборд **«WiFi-Guard — метрики безопасности»**
  (он же в Dashboards → WiFi-Guard). Справа вверху поставь интервал **Last 3 hours**;
* `http://192.168.56.10:9090/alerts` — правила оповещения: девять правил, все зелёные (Inactive).

Если порт-форвард оборвался (`lost connection to pod`), просто запусти команду снова.

---

## 3. Создать ВМ1 «нарушитель»

ВМ3 на время установки лучше выключить, чтобы хватило памяти: `minikube stop -p wifi-guard`, затем `sudo poweroff`.

1. VirtualBox → **Создать**: имя `wg-attacker`, тот же ISO Ubuntu Server 24.04, «Пропустить автоматическую установку».
2. ОЗУ **2048 МБ** (только на время установки), ЦП **1**, диск **10 ГБ**.
3. **Настроить → Сеть:**
   * Адаптер 1: **NAT**;
   * Адаптер 2: **Виртуальный адаптер хоста**, та же сеть host-only;
   * Адаптер 3: включить, **Внутренняя сеть**, имя впиши вручную: `evil-twin`.
4. Установка, как в разделе 4 первой методички, но на экране **Network**:
   * `enp0s8` → Edit IPv4 → Manual: Subnet `192.168.56.0/24`, Address `192.168.56.30`;
   * `enp0s9` → Edit IPv4 → Manual: Subnet `10.10.10.0/24`, Address `10.10.10.1`.

   Profile: name `laloni`, server name **`wg-attacker`**, username `laloni`. Галочка **Install OpenSSH server**.
   Диск: можно оставить по умолчанию (без расширения LVM).
5. После установки выключи ВМ и уменьши ОЗУ до **1024 МБ**.

---

## 4. Создать ВМ2 «пользователь» клонированием

1. Выдели выключенную `wg-attacker` → правая кнопка → **Клонировать**: имя `wg-user`,
   политика MAC-адресов **«Сгенерировать новые MAC-адреса для всех адаптеров»**, **Полное клонирование**.
2. Запусти `wg-user` и войди в консоль окна VirtualBox. Поменяй адреса и имя:
   ```bash
   sudo sed -i 's#192.168.56.30/24#192.168.56.20/24#; s#10.10.10.1/24#10.10.10.20/24#' /etc/netplan/50-cloud-init.yaml && sudo netplan apply
   ```
   ```bash
   sudo hostnamectl set-hostname wg-user && ip -4 -br addr
   ```
   Ожидается `enp0s8 … 192.168.56.20/24` и `enp0s9 … 10.10.10.20/24`.
3. Запусти `wg-attacker` и `wg-server`, затем подними кластер на `wg-server` (раздел 15 первой методички) и
   выполни `./scripts/expose-gateway.sh`.

Проверка связи. **PowerShell:**
```powershell
ping -n 2 192.168.56.20; ping -n 2 192.168.56.30
```

📸 **Скриншот 4.2:** окно VirtualBox с тремя запущенными ВМ, у `wg-user` открыта вкладка «Сеть» (видны три адаптера).

---

## 5. Подготовить ВМ2 «пользователь»

**PowerShell:** `ssh laloni@192.168.56.20`, затем в **ВМ2**:

```bash
sudo apt update && sudo apt install -y python3-httpx python3-pytest
```

Скопировать с сервера клиента, сертификаты устройства пользователя и администратора, а также сертификат нарушителя для
теста С2 в pytest:

```bash
mkdir -p ~/lab && ssh laloni@192.168.56.10 "tar -C ~/wifi-guard -cz client/client_sim.py client/experiment.py client/test_cluster.py certs/ca.crt certs/user1.crt certs/user1.key certs/admin1.crt certs/admin1.key certs/attacker.crt certs/attacker.key scripts/lab/wifi.sh" | tar -xz -C ~/lab
```

```bash
cd ~/lab && mv client/* . && mv scripts/lab/wifi.sh . && rmdir -p client scripts/lab 2>/dev/null; ls
```

Ожидается: `certs  client_sim.py  experiment.py  test_cluster.py  wifi.sh`.

```bash
echo 'export WG_BASE=https://192.168.56.10:8443' >> ~/.bashrc && source ~/.bashrc
```

**Калибровка эталона маршрута с места легитимного клиента.** Она заменяет калибровку из ВМ3 или Windows:

```bash
cd ~/lab && sudo ./wifi.sh legit && python3 client_sim.py --base $WG_BASE --scenario calibrate --ca certs/ca.crt --admin-cert certs/admin1.crt --admin-key certs/admin1.key
```

Ожидается `POST /api/admin/aps -> 201 {... "ref_hops":2 ...}`. Это значит: ВМ2 → ВМ3 (DNAT) → узел кластера → под шлюза.
Подожди **30 секунд**: столько микросервис безопасности кэширует реестр.

```bash
python3 client_sim.py --base $WG_BASE --scenario normal --ca certs/ca.crt --cert certs/user1.crt --key certs/user1.key
```

Ожидается `200` и `"verdict":"ALLOW"`.

---

## 6. Подготовить ВМ1 «нарушитель»

**PowerShell:** `ssh laloni@192.168.56.30`, затем в **ВМ1**:

```bash
sudo apt update && sudo apt install -y python3-httpx nmap
```

Нарушителю достаются только клиент и сертификат **его собственного** устройства. Это устройство другого сотрудника,
выпущенное тем же УЦ. Закрытого ключа пользователя у него нет:

```bash
mkdir -p ~/lab && ssh laloni@192.168.56.10 "tar -C ~/wifi-guard -cz client/client_sim.py client/experiment.py certs/ca.crt certs/attacker.crt certs/attacker.key scripts/lab/rogue-ap.sh" | tar -xz -C ~/lab
```

```bash
cd ~/lab && mv client/* . && mv scripts/lab/rogue-ap.sh . && rmdir -p client scripts/lab 2>/dev/null; ls
```

Ожидается: `certs  client_sim.py  experiment.py  rogue-ap.sh`.

```bash
echo 'export WG_BASE=https://192.168.56.10:8443' >> ~/.bashrc && source ~/.bashrc
```

📌 Снимки ВМ: `wg-user` и `wg-attacker` → «01 готово к испытаниям».

---

## 7. Испытания: системные тесты pytest (ВМ2)

```bash
cd ~/lab && mkdir -p results && sudo ./wifi.sh legit && python3 -m pytest -v test_cluster.py | tee results/pytest.txt
```

Ожидается `12 passed`.

📸 **Скриншот 4.3:** вывод pytest.

---

## 8. Испытания: серии атак

Каждая серия — 100 попыток. Скрипт печатает сводку: исходы, долю ошибок с верхней 95-процентной границей и время
ответа. Всё дописывается в `results/summary.txt`, по каждой попытке сохраняется CSV. Серия идёт около минуты.
Grafana держи открытой: графики меняются по ходу испытаний.

### 8.1. Легитимная работа и двойник в эфире (ВМ2, легитимная ТД)

```bash
cd ~/lab && sudo ./wifi.sh legit
```

**Э1** — легитимный пользователь (проверка ложных срабатываний):
```bash
python3 experiment.py --base $WG_BASE --scenario normal --label "Э1 ВМ2 легитимная ТД" --csv results/e1-normal.csv | tee -a results/summary.txt
```

**Э2** — клиент у легитимной ТД, но в эфире появился двойник:
```bash
python3 experiment.py --base $WG_BASE --scenario relay --label "Э2 ВМ2 легитимная ТД, двойник в эфире" --csv results/e2-relay-legit.csv | tee -a results/summary.txt
```

### 8.2. Сценарий С1: клиент на подменной ТД

**ВМ1** — включить подменную ТД:
```bash
cd ~/lab && sudo ./rogue-ap.sh start
```

**ВМ2** — «деаутентификация» и переподключение к двойнику:
```bash
sudo ./wifi.sh twin
```

Ожидается `… via 10.10.10.1 dev enp0s9`, то есть трафик к серверу идёт через нарушителя.

**ВМ3** — проверка, что TTL-зонд видит лишний узел. Отправь один запрос с ВМ2
(`python3 client_sim.py --base $WG_BASE --scenario normal --ca certs/ca.crt --cert certs/user1.crt --key certs/user1.key`),
затем на ВМ3:
```bash
for ip in 192.168.56.20 192.168.56.30; do kubectl -n wg-edge exec deploy/gateway -c gateway -- python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:9100/hops?ip=$ip').read().decode())"; done
```

Ожидается для `192.168.56.30` (адрес подменной ТД после NAT) `"hops": 3`, а для `192.168.56.20` от калибровки — `2`.
📸 **Скриншот 4.4:** этот вывод.

Серии на **ВМ2**:

**Э3** — «идеальный клон»: BSSID, канал и PMF скопированы, двойник в эфире не виден:
```bash
python3 experiment.py --base $WG_BASE --scenario clone --label "Э3 ВМ2 через ВМ1, идеальный клон" --csv results/e3-clone.csv | tee -a results/summary.txt
```

**Э4** — ретранслирующий двойник, виден в эфире:
```bash
python3 experiment.py --base $WG_BASE --scenario relay --label "Э4 ВМ2 через ВМ1, ретранслятор" --csv results/e4-relay-twin.csv | tee -a results/summary.txt
```

**Э5** — двойник без PMF:
```bash
python3 experiment.py --base $WG_BASE --scenario evil-twin --label "Э5 ВМ2 через ВМ1, без PMF" --csv results/e5-evil-twin.csv | tee -a results/summary.txt
```

**Э6** — подставная ТД с чужим BSSID:
```bash
python3 experiment.py --base $WG_BASE --scenario rogue-ap --label "Э6 ВМ2 через ВМ1, чужой BSSID" --csv results/e6-rogue-ap.csv | tee -a results/summary.txt
```

Вернуть пользователя на легитимную ТД (**ВМ2**) и выключить подменную (**ВМ1**):
```bash
sudo ./wifi.sh legit
```
```bash
sudo ./rogue-ap.sh stop
```

📸 **Скриншот 4.5:** вкладка Prometheus Alerts (`http://192.168.56.10:9090/alerts`), пока горят оповещения после
серий Э2–Э6 (5 минут после окончания).

### 8.3. Сценарий С2: подмена клиента (ВМ1)

**ВМ2** — пользователь входит в систему, его токен «перехватывается»:
```bash
python3 experiment.py --base $WG_BASE --scenario export-token --token-file results/token.txt
```

**ВМ1** — нарушитель получил токен:
```bash
cd ~/lab && mkdir -p results && scp laloni@192.168.56.20:~/lab/results/token.txt results/token.txt
```

**Э7** — перехваченный токен с устройства нарушителя:
```bash
python3 experiment.py --base $WG_BASE --scenario stolen-token --token-file results/token.txt --cert certs/attacker.crt --key certs/attacker.key --label "Э7 ВМ1 чужой токен" --csv results/e7-stolen.csv | tee -a results/summary.txt
```

**Э8** — тот же токен без сертификата устройства:
```bash
python3 experiment.py --base $WG_BASE --scenario no-cert --token-file results/token.txt --cert certs/attacker.crt --key certs/attacker.key --label "Э8 ВМ1 токен без сертификата" --csv results/e8-nocert.csv | tee -a results/summary.txt
```

**Э9** — токен с подделанной ролью `admin`:
```bash
python3 experiment.py --base $WG_BASE --scenario forged-token --token-file results/token.txt --cert certs/attacker.crt --key certs/attacker.key --label "Э9 ВМ1 поддельный токен" --csv results/e9-forged.csv | tee -a results/summary.txt
```

**Э10** — перебор паролей без пауз. Ожидается `401`, а затем `RATE_LIMIT` (429) от ограничения NGINX:
```bash
python3 experiment.py --base $WG_BASE --scenario password-guess --runs 40 --interval 0 --cert certs/attacker.crt --key certs/attacker.key --label "Э10 ВМ1 перебор паролей" --csv results/e10-guess.csv | tee -a results/summary.txt
```

### 8.4. Поверхность атаки и отказоустойчивость

**Э11 (ВМ1)** — какие порты сервера видит нарушитель (занимает 1–2 минуты):
```bash
sudo nmap -Pn -sT -p- --min-rate 2000 192.168.56.10 | tee results/nmap.txt
```

Ожидается открыто только `22/tcp ssh` и `8443/tcp`.

**Э12 (ВМ1)** — попытка обойти шлюз: маршрут в сеть кластера через сервер и обращение к API Kubernetes:
```bash
sudo ip route add 192.168.49.0/24 via 192.168.56.10; curl -sk -m 5 https://192.168.49.2:8443/version || echo "API Kubernetes недоступен"; sudo ip route del 192.168.49.0/24
```

Ожидается `API Kubernetes недоступен`.

**Э13** — «закрыт при сбое». **ВМ3:** остановить микросервис безопасности:
```bash
kubectl -n wg-core scale deployment/security --replicas=0
```

**ВМ2** — 20 попыток легитимного пользователя:
```bash
python3 experiment.py --base $WG_BASE --scenario normal --runs 20 --label "Э13 ВМ2 микросервис безопасности остановлен" --csv results/e13-failclosed.csv | tee -a results/summary.txt
```

Ожидается `FAIL_CLOSED` (503) во всех попытках. **ВМ3** — вернуть микросервис:
```bash
kubectl -n wg-core scale deployment/security --replicas=1 && kubectl -n wg-core rollout status deployment/security
```

---

## 9. Время реакции мониторинга (ВМ3)

Prometheus хранит историю оповещений. Скрипт выводит, когда каждое из них перешло в состояние «сработало» (firing).
Окно B с пробросом Prometheus должно быть запущено:

```bash
cd ~/wifi-guard && python3 scripts/lab/alert-times.py 3 | tee ~/alerts.txt
```

Время первой попытки каждой серии есть в CSV (колонка `ts`). Разница показывает, через сколько секунд после начала
атаки администратор получил оповещение. Я посчитаю её сам по присланным файлам.

---

## 10. Дашборд

После всех серий открой дашборд, поставь интервал на всё время испытаний (например, **Last 1 hour**) и сделай:

📸 **Скриншот 4.6:** дашборд целиком. Масштаб браузера 67–80 %, чтобы влезли все панели.
📸 **Скриншот 4.7:** крупно панели «Вердикты…» и «Срабатывания индикаторов…» в момент серий С1.

---

## 11. Что прислать мне

1. Архивы результатов. **ВМ2** и **ВМ1**:
   ```bash
   cd ~/lab && tar czf results-$(hostname).tgz results
   ```
   **PowerShell:**
   ```powershell
   scp laloni@192.168.56.20:~/lab/results-wg-user.tgz $HOME\Desktop\ ; scp laloni@192.168.56.30:~/lab/results-wg-attacker.tgz $HOME\Desktop\ ; scp laloni@192.168.56.10:~/alerts.txt $HOME\Desktop\
   ```
2. Скриншоты 4.1–4.7.
3. Если что-то пошло не так — вывод команды целиком.

По этим данным я напишу 4.1 и 4.2 с таблицами результатов, проверкой гипотезы и рисунками.

---

## 12. Если что-то пошло не так

| Симптом | Причина и решение |
|---|---|
| Э1 даёт `SUSPICIOUS`, а не `ALLOW` | эталон калибровался не с ВМ2 или ВМ2 на подменной ТД: `sudo ./wifi.sh legit`, повтори калибровку (раздел 5), подожди 30 с |
| Э3/Э4 не видят лишнего узла (`ALLOW` у clone) | не запущена подменная ТД на ВМ1 (`sudo ./rogue-ap.sh status`) или ВМ2 не переключена (`sudo ./wifi.sh status` должно показать `via 10.10.10.1`) |
| `wifi.sh twin`: `Nexthop has invalid gateway` | у ВМ2 нет адреса `10.10.10.20` на `enp0s9`: проверь `ip -br addr` и раздел 4 |
| Много `RATE_LIMIT` в Э1–Э9 | уменьшилась пауза: не задавай `--interval` меньше 0,25 (ограничение NGINX — 10 запросов/с) |
| `ConnectError` / `Connection refused` | на ВМ3 после перезагрузки не выполнен `./scripts/expose-gateway.sh` |
| `CERTIFICATE_VERIFY_FAILED … IP address mismatch` | в сертификате шлюза нет `192.168.56.10`: `cert_extra_ips` (раздел 9 первой методички) |
| На дашборде «No data» | Prometheus ещё не собрал метрики (до 15 с) или не перезапущен аудит (раздел 1, п. 5) |
| `apt install python3-httpx` не находит пакет | `sudo apt update`, затем повтори |
| Не хватает памяти, ВМ тормозят | ВМ1 и ВМ2 нужны по 1 ГБ; закрой лишние программы на Windows |
