# WiFi-Guard — паттерн безопасности приложения при угрозе подмены беспроводного клиента или точки доступа

Программная часть курсовой работы (главы 3 и 4). Пять микросервисов на Python 3.12 + FastAPI,
развертывание в Kubernetes (minikube) с помощью Ansible, мониторинг в Prometheus и Grafana.

Репозиторий: https://github.com/LaloniBley/Wifi-Guard

> Развертывание на виртуальной машине VirtualBox с нуля (установка Ubuntu, Docker, minikube, проверки и
> скриншоты для отчёта) — в [docs/GUIDE-VirtualBox.md](docs/GUIDE-VirtualBox.md).
> Испытательный стенд из трёх ВМ (нарушитель, пользователь, сервер), серии атак и мониторинг (глава 4) —
> в [docs/GUIDE-chapter4.md](docs/GUIDE-chapter4.md).

Паттерн защищает приложение «Корпоративный портал» от угрозы **УБИ.126** БДУ ФСТЭК России:

* **сценарий С1** — подмена точки доступа («злой двойник»): клиент переподключился к ТД нарушителя;
* **сценарий С2** — подмена клиента: нарушитель перехватил сессионный токен и предъявляет его со своего устройства.

---

## 1. Что нужно установить

VS Code и PyCharm у тебя уже есть. Всё остальное ставится в **WSL2 (Ubuntu)** — Linux внутри Windows.
Это нужно потому, что Ansible не работает на Windows, а у minikube в Linux самая простая сетевая настройка.

| № | Что | Зачем | Как установить |
|---|-----|-------|----------------|
| 1 | WSL2 + Ubuntu 24.04 | Linux-среда для всего остального | PowerShell **от администратора**: `wsl --install -d Ubuntu-24.04`, затем перезагрузка |
| 2 | Docker Engine (внутри Ubuntu) | контейнеры и драйвер minikube | `curl -fsSL https://get.docker.com \| sudo sh` и `sudo usermod -aG docker $USER`, затем перезайти в Ubuntu |
| 3 | kubectl | управление кластером | см. блок команд ниже |
| 4 | minikube | локальный кластер Kubernetes | см. блок команд ниже |
| 5 | Python-окружение + Ansible | тесты, симулятор клиента, плейбук | см. блок команд ниже |
| 6 | Расширение VS Code **WSL** | открыть проект из Ubuntu в VS Code | в VS Code: Extensions → «WSL» (Microsoft) |
| 7 | Postman (по желанию) | ручные запросы и «атаки» в главе 4 | https://www.postman.com/downloads/ |

> Docker Desktop тоже подойдёт (включи WSL integration), но тогда IP-адрес minikube не будет доступен из
> Ubuntu напрямую — придётся использовать `kubectl port-forward` (см. раздел 6). Поэтому рекомендую Docker Engine внутри Ubuntu.

Команды для пунктов 3–5 (выполнять в терминале Ubuntu):

```bash
sudo apt update && sudo apt install -y python3-venv git openssl unzip

# kubectl
curl -LO "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl

# minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64

# проект и Python-окружение
git clone https://github.com/LaloniBley/Wifi-Guard.git ~/wifi-guard
cd ~/wifi-guard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt ansible-core kubernetes
ansible-galaxy collection install -r ansible/requirements.yml
```

Требования к ноутбуку: **8 ГБ свободной ОЗУ** для кластера (на ноутбуке с 16 ГБ — без проблем), 4 ядра, ~30 ГБ на диске.
Если ОЗУ меньше, уменьши `minikube_memory_mb` в `ansible/group_vars/all.yml` до 6144 — Oracle запустится, но медленнее.

---

## 2. Структура проекта

```
wifi-guard/
├── common/wg_common/          общий модуль: настройки, БД, аудит, нормализация MAC
├── services/
│   ├── Dockerfile             единый Dockerfile Python-микросервисов
│   ├── gateway/wg_gateway/    шлюз доступа (API Gateway)
│   ├── ttl-probe/wg_ttlprobe/ TTL-зонд (контейнер в поде шлюза) + свой Dockerfile
│   ├── auth/wg_auth/          аутентификация и верификация (JWT, PBKDF2)
│   ├── security/wg_security/  микросервис безопасности (правила обнаружения подмены)
│   ├── registry/wg_registry/  справочные данные: реестр доверенных ТД
│   ├── audit/wg_audit/        мониторинг и аудит: журнал + метрики Prometheus
│   └── portal/wg_portal/      защищаемое приложение «Корпоративный портал»
├── client/
│   ├── client_sim.py          симулятор клиентской части (легитимный клиент и атаки)
│   ├── experiment.py          серийные испытания: 100 попыток сценария, доли исходов, время ответа
│   └── test_cluster.py        системные тесты pytest на развёрнутом кластере (WG_BASE=https://…)
├── tests/                     37 автотестов pytest (без кластера); tests/prometheus — тесты правил promtool
├── deploy/k8s/                манифесты Kubernetes (kustomize)
│   └── monitoring/            Prometheus: конфигурация и правила (wg-rules.yml); Grafana: дашборд
├── ansible/                   плейбуки развертывания и удаления
├── scripts/                  gen-certs.sh — сертификаты УЦ; expose-gateway.sh — публикация шлюза на IP ВМ;
│                              build-dashboard.py — генерация дашборда Grafana
│   └── lab/                   стенд главы 4: rogue-ap.sh (ВМ нарушителя), wifi.sh (ВМ пользователя),
│                              alert-times.py (время срабатывания оповещений)
├── docs/GUIDE-VirtualBox.md  гайд: развертывание на ВМ VirtualBox с нуля
├── docs/GUIDE-chapter4.md    гайд: испытательный стенд, тестирование и мониторинг (глава 4)
├── docs/diagrams/             исходники блок-схем (ГОСТ 19.701-90) и схемы развертывания
└── .github/workflows/ci.yml   CI/CD: тесты, проверка манифестов, сборка образов в GHCR
```

---

## 3. Как работает паттерн (кратко)

```
Клиент ──HTTPS+сертификат устройства──► [Pod gateway: nginx → gateway, ttl-probe]
                                              │
             1. сертификат проверен?  (нет → 401)
             2. токен верен и привязан к этому сертификату? ──► auth      (нет → 401)
             3. признаки подмены ТД/клиента?               ──► security  (BLOCK → 403 + отзыв сессии)
                                                                  └─► registry (эталоны ТД)
             4. запрос передаётся в portal
             все события ──► audit ──► Prometheus ──► Grafana
```

### 3.1. Шлюз доступа (`services/gateway`)
Единственная точка входа. В поде три контейнера:

* **nginx** — принимает HTTPS на порту 8443 и проверяет сертификат устройства (mTLS). Передаёт шлюзу заголовки
  `X-Client-Verify`, `X-Client-Cert`, `X-Real-IP` (перезаписывает их — клиент подделать не может).
* **gateway** (FastAPI, слушает только `127.0.0.1:8080`) — конвейер проверок:
  * `cert_thumbprint()` — отпечаток сертификата SHA-256 (формат x5t#S256, RFC 8705);
  * `parse_telemetry()` — разбирает заголовок `X-WG-Telemetry` (base64url JSON: SSID, BSSID, PMF, список видимых сетей);
  * `verify_token()` → микросервис auth; `security_verdict()` → микросервис security;
  * маршрут `/portal/*` — всё вместе + проксирование в портал;
  * маршрут `/api/login` — вход (сначала проверка ТД, потом выдача токена);
  * маршрут `/api/admin/aps` — онбординг ТД администратором (с `calibrate: true` эталон hops берётся из текущего подключения).
  * Если auth/security не отвечают 2 с — **503** (принцип fail-closed).
* **ttl-probe** — читает IPv4-пакеты сырым сокетом (`AF_PACKET`), запоминает TTL каждого клиента, отвечает на
  `GET /hops?ip=...`. `hops = начальный_TTL − TTL`, где начальный TTL — ближайшее сверху из {32, 64, 128, 255}.
  Использует только стандартную библиотеку Python. Нужна привилегия NET_RAW.

### 3.2. Аутентификация и верификация (`services/auth`)
* Пароли: PBKDF2-HMAC-SHA256, 600 000 итераций, соль 16 байт (`passwords.py`).
* Токен: JWT HS256 на 15 минут с полями `cnf.x5t#S256` (отпечаток сертификата устройства) и `ctx` (BSSID, hops при входе) — `tokens.py`.
* `POST /internal/verify` — подпись, срок, привязка к сертификату, сессия не отозвана. Причины отказа:
  `token_invalid`, `token_expired`, `no_client_certificate`, `binding_mismatch` (сценарий С2), `session_revoked`, `unknown_session`.
* `POST /internal/revoke` — отзыв сессии (вызывает микросервис безопасности при блокировке).
* Таблицы Oracle: `WG_USERS`, `WG_SESSIONS`.

### 3.3. Микросервис безопасности (`services/security`)
Ядро паттерна. Правила в `rules.py`, функция `assess()` — без сети и БД, поэтому легко тестируется.

| Индикатор | Условие | Вес |
|-----------|---------|-----|
| K1 `BSSID_UNTRUSTED` | ТД нет в реестре / другая сеть / нет телеметрии | 1,0 |
| K2 `PMF_NOT_NEGOTIATED` | реестр требует PMF (802.11w), а он не согласован | 1,0 |
| N1 `HOPS_DEVIATION` | число транзитных узлов ≠ эталону ТД | 0,4 |
| N2 `TWIN_IN_AIR` | в эфире двойник: тот же SSID с чужим BSSID или клон BSSID на другом канале/с другой защитой | 0,4 |

Вердикт: `score ≥ 0,8` → **BLOCK** (403, сессия отзывается); `score ≥ 0,4` → **SUSPICIOUS** (пропуск, но событие с
повышенной важностью); иначе **ALLOW**. Смысл: один критический признак или два слабых = блокировка.
Пороги меняются переменными окружения `BLOCK_THRESHOLD`, `SUSPICIOUS_THRESHOLD`, `HOPS_TOLERANCE`.

### 3.4. Справочные данные и реестры (`services/registry`)
Реестр доверенных ТД (`WG_TRUSTED_APS`): BSSID, SSID, канал, режим защиты, требование PMF, эталон hops.
Чтение — `GET /aps/{bssid}`, `GET /aps?ssid=`; изменение — только с заголовком `X-Admin-Key`.
Начальный реестр берётся из ConfigMap `wg-trusted-aps` (при перезапуске калибровка не затирается).

### 3.5. Мониторинг и аудит (`services/audit`)
`POST /events` — сохраняет событие в `WG_AUDIT_EVENTS` и обновляет метрики; `GET /events` — журнал;
`GET /metrics` — для Prometheus. Метрики: `wg_verdicts_total`, `wg_indicators_total`, `wg_auth_failures_total`,
`wg_sessions_revoked_total`, `wg_gateway_requests_total`, `wg_risk_score`, `wg_gateway_latency_seconds`.
Все ожидаемые ряды счётчиков создаются при старте с нулём, чтобы первое же событие учитывалось функцией
`increase()` в Prometheus.

Prometheus вычисляет по ним показатели безопасности (доля блокировок, доля подозрительных запросов, попытки
использовать чужой токен, 95-й процентиль задержки шлюза) и девять правил оповещения: подменная ТД, двойник
в эфире, изменение маршрута, чужой и поддельный токен, перебор паролей, отказ «закрыт при сбое», медленный шлюз,
недоступность аудита (`deploy/k8s/monitoring/wg-rules.yml`). Grafana при запуске загружает дашборд
«WiFi-Guard — метрики безопасности» (`deploy/k8s/monitoring/wifi-guard-security.json`, генерируется
`scripts/build-dashboard.py`).

### 3.6. Портал (`services/portal`) и симулятор (`client/client_sim.py`)
Портал отвечает только на запросы с заголовком `X-WG-User` от шлюза. Симулятор формирует телеметрию и
делает запросы по mTLS в режимах: `normal`, `rogue-ap`, `evil-twin`, `relay`, `stolen-token`, `calibrate`.

---

## 4. Проверка кода без кластера (2 минуты)

```bash
source .venv/bin/activate
pytest -q          # 37 тестов: правила, токены, TTL, метрики, сквозные сценарии С1/С2
```

Все сервисы поднимаются в одном процессе, вместо Oracle — SQLite в памяти.

---

## 5. Развертывание в кластере

```bash
cd ~/wifi-guard && source .venv/bin/activate
cd ansible
ansible-playbook -i inventory.ini deploy.yml
```

Плейбук сам: запустит minikube (профиль `wifi-guard`, CNI Calico, 4 CPU / 8 ГБ), соберёт 7 образов внутри
minikube, выпустит сертификаты в `certs/`, сгенерирует секреты в `ansible/.secrets/`, создаст namespace'ы и
Secret'ы, применит манифесты и дождётся готовности. **Первый запуск — 15–25 минут** (скачивание образа Oracle
~1,5 ГБ и создание БД). Повторный запуск безопасен.

Проверка:

```bash
kubectl get pods -A -l app.kubernetes.io/part-of=wifi-guard     # все поды Running/Ready
kubectl get networkpolicy -A                                     # 16 политик
NODE=$(minikube -p wifi-guard ip)
cd ~/wifi-guard

# 1) один раз — калибровка эталона hops для ТД CORP-WIFI (вход администратора)
python client/client_sim.py --base https://$NODE:30443 --scenario calibrate

# 2) легитимный клиент → 200, X-WG-Verdict: ALLOW
python client/client_sim.py --base https://$NODE:30443 --scenario normal
# 3) атаки
python client/client_sim.py --base https://$NODE:30443 --scenario rogue-ap      # 403 при входе (С1)
python client/client_sim.py --base https://$NODE:30443 --scenario evil-twin     # 403, сессия отозвана (С1)
python client/client_sim.py --base https://$NODE:30443 --scenario relay         # 200, SUSPICIOUS
python client/client_sim.py --base https://$NODE:30443 --scenario stolen-token  # 401 binding_mismatch (С2)
```

Проверка сетевой изоляции (портал не должен быть доступен напрямую — ожидается тайм-аут):

```bash
kubectl run nettest -n default --rm -it --image=busybox:1.36 --restart=Never -- \
  wget -T 3 -qO- http://portal.wg-core.svc.cluster.local:8000/healthz
```

Журнал аудита и метрики:

```bash
kubectl -n wg-monitoring port-forward svc/audit 8004:8004 &
curl -s "http://127.0.0.1:8004/events?limit=5" | python3 -m json.tool
curl -s http://127.0.0.1:8004/metrics | grep ^wg_

kubectl -n wg-monitoring port-forward svc/grafana 3000:3000     # http://localhost:3000, admin / пароль в ansible/.secrets/grafana
```

Удаление: `ansible-playbook -i inventory.ini teardown.yml` (кластер остаётся), полностью — `minikube delete -p wifi-guard`.

---

## 6. Postman

1. `kubectl -n wg-edge port-forward svc/gateway 8443:443 --address 0.0.0.0` (в Ubuntu).
2. В Postman: Settings → Certificates → Add Certificate: host `localhost:8443`, PFX-файл `certs/user1.p12`, пароль `wifiguard`;
   CA Certificates → `certs/ca.crt`.
3. Запрос `POST https://localhost:8443/api/login`, тело `{"username":"ivanov","password":"Ivanov#2026"}`,
   заголовок `X-WG-Telemetry` — значение возьми из `python -c "import sys; sys.path.insert(0,'client'); from client_sim import telemetry_for; print(telemetry_for('normal'))"`.

> Через `port-forward` трафик приходит в под по loopback-интерфейсу, поэтому TTL-зонд видит hops = 0, и при
> откалиброванном эталоне запрос получит вердикт SUSPICIOUS (индикатор N1). Это нормально — это и есть
> срабатывание признака «изменился маршрут».

---

## 7. Учётные записи и сертификаты (демо)

| Кто | Логин / пароль | Сертификат |
|-----|----------------|------------|
| Пользователь | `ivanov` / `Ivanov#2026` | `certs/user1.*` |
| Администратор | `admin` / `Admin#2026` | `certs/admin1.*` |
| Нарушитель (С2) | — (крадёт токен ivanov) | `certs/attacker.*` |

Пароли пользователей задаются переменной `demo_users` в `ansible/group_vars/all.yml`.

---

## 8. Если что-то не работает

| Симптом | Причина / решение |
|---------|-------------------|
| `auth`, `registry`, `audit` долго не Ready | Oracle ещё создаёт БД: `kubectl -n wg-data logs oracle-0 -f`, ждать строку `DATABASE IS READY TO USE!` |
| Поды Oracle в `Pending` / `OOMKilled` | не хватает памяти узлу: увеличь `minikube_memory_mb` или закрой лишние программы |
| Политики не блокируют трафик | кластер создан без Calico: `minikube delete -p wifi-guard` и повтор плейбука |
| `client_sim` не подключается к `192.168.49.2` | используется Docker Desktop — бери `port-forward` (раздел 6) и `--base https://localhost:8443` |
| В тестах `ModuleNotFoundError` | не активировано окружение: `source .venv/bin/activate` |

---

## 9. Публикация в GitHub (первый раз)

Распакуй архив и выполни в папке проекта (в Ubuntu или Git Bash):

```bash
git init -b main
git add .
git commit -m "WiFi-Guard: микросервисы, манифесты, Ansible, CI"
git remote add origin https://github.com/LaloniBley/Wifi-Guard.git
git push -u origin main
```

После push во вкладке **Actions** запустится конвейер `ci`: тесты и ruff, проверка манифестов kubeconform,
затем сборка 7 образов в GitHub Container Registry (`ghcr.io/lalonibley/wifi-guard-<сервис>`).
Сертификаты (`certs/`) и секреты (`ansible/.secrets/`) в репозиторий не попадают — они в `.gitignore`.
Если сборка образов упадёт с ошибкой прав на пакеты: Settings → Actions → General →
Workflow permissions → **Read and write permissions**.
