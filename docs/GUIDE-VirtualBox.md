# Методичка: развертывание WiFi-Guard на ВМ VirtualBox (Ubuntu) с нуля

Версия 2 — с учётом всех исправлений после первого прогона.

Пошагово: от установки VirtualBox и Ubuntu до полностью развёрнутого паттерна из главы 3,
проверенных атак С1/С2 и скриншотов для отчёта. В конце будут работать:
* пять микросервисов в Kubernetes, 4 пространства имён и 16 сетевых политик;
* Oracle, Prometheus и Grafana.

**Время:** 2–3 часа, из них около часа уходит на скачивание и ожидание.

```
Windows (ноутбук)  ── 192.168.56.1
 └─ VirtualBox
     └─ ВМ Ubuntu Server 24.04 ── 192.168.56.10 (сеть host-only)
         └─ Docker Engine
             └─ minikube 192.168.49.2 (Kubernetes v1.31, CNI Calico)
                 ├─ wg-edge        шлюз доступа (nginx + gateway + ttl-probe), NodePort 30443
                 ├─ wg-core        auth, security, registry, portal
                 ├─ wg-data        Oracle Database 23ai Free
                 └─ wg-monitoring  audit, Prometheus, Grafana
```

### Как пользоваться методичкой

* **Одна команда — один блок.** Копируй блок целиком, вставляй в терминал и жми Enter. Следующий блок — только после
  того, как предыдущий закончился и снова появилось приглашение `$`.
* Команды для **Windows** помечены «PowerShell». Все остальные выполняются **в ВМ** (по SSH).
* В примерах пользователь ВМ — `laloni`, адрес — `192.168.56.10`. Если у тебя другие, подставь свои.
* 📸 отмечены скриншоты для главы 3.

---

## 0. Если ты уже ставил раньше — снести старое

В VirtualBox: выдели старую ВМ → правая кнопка → **Удалить** → **Удалить все файлы**.
Сеть host-only из раздела 2 удалять не нужно: если она уже есть, этот раздел можно пропустить.

На Windows удали старые сертификаты (PowerShell):

```powershell
Remove-Item -Recurse -Force $HOME\wg\certs -ErrorAction SilentlyContinue
```

`client_sim.py` в папке `wg` уже обновлён до последней версии, его не трогай.

---

## 1. Требования к ноутбуку

Самый тяжёлый компонент — Oracle: ему нужно до 3 ГБ ОЗУ. Объём памяти ноутбука смотри в Диспетчере задач →
Производительность → Память.

| ОЗУ ноутбука | ОЗУ для ВМ | ЦП для ВМ | `minikube_memory_mb` (раздел 9) |
|---|---|---|---|
| 16 ГБ | 10 240 МБ | 4 | 7168 |
| 32 ГБ и больше | 14 336 МБ | 6 | 8192 |

Ещё нужно 60 ГБ свободного места на диске.

---

## 2. Подготовка Windows и VirtualBox

1. **Виртуализация включена?** Диспетчер задач → Производительность → ЦП → «Виртуализация: Включено».
   Если отключено — включить *Intel VT-x* или *AMD-V (SVM)* в BIOS/UEFI.
2. **Скачай:**
   * VirtualBox 7.x для Windows: https://www.virtualbox.org/wiki/Downloads
   * Ubuntu Server **24.04 LTS**: файл `ubuntu-24.04.x-live-server-amd64.iso` с https://releases.ubuntu.com/24.04/
3. Установи VirtualBox с настройками по умолчанию.
4. **Сеть host-only** (через неё Windows и будущие ВМ видят сервер):
   VirtualBox → Файл → Инструменты → **Менеджер сетей** → вкладка **Host-only Networks** → **Создать**. Затем:
   * вкладка «Адаптер»: «Настроить адаптер вручную», IPv4 `192.168.56.1`, маска `255.255.255.0`;
   * вкладка «DHCP-сервер»: **снять** галочку «Включить сервер» → Применить.
5. Если ВМ потом будет тормозить (в углу окна ВМ значок черепахи), нужно выключить Hyper-V. PowerShell от администратора:
   `bcdedit /set hypervisorlaunchtype off`, затем перезагрузка.

---

## 3. Создание ВМ

1. **Создать**: имя `wg-server`, ISO — скачанный образ, галочка **«Пропустить автоматическую установку»**.
2. **Оборудование:** ОЗУ и ЦП — из таблицы раздела 1.
3. **Диск:** новый, **60 ГБ**, VDI, динамический.
4. **Готово** → выдели ВМ → **Настроить**:
   * Система → Процессор: включить **PAE/NX**;
   * Сеть → Адаптер 1: **NAT**;
   * Сеть → Адаптер 2: включить, **Виртуальный адаптер хоста** (Host-only), сеть из раздела 2.

---

## 4. Установка Ubuntu Server 24.04

Запусти ВМ. Управление в установщике — стрелки, Enter, Tab.

1. Language: **English**; Keyboard: **English (US)**; Type: **Ubuntu Server**.
2. **Network** — самый важный экран:
   * `enp0s3` (NAT) — получит адрес `10.0.2.15` автоматически, не трогай;
   * `enp0s8` → **Edit IPv4** → Method **Manual**:
     Subnet `192.168.56.0/24`, Address `192.168.56.10`, остальные поля **пустые** → Save.
3. Proxy — пусто; Mirror — по умолчанию.
4. **Storage:** «Use an entire disk» + LVM. На экране Storage configuration выбери `ubuntu-lv` → **Edit** → **Size** на максимум → Save → Done → Continue.
5. **Profile:** name `laloni`, server name `wg-server`, username `laloni`, пароль запомни.
6. Ubuntu Pro — Skip. **SSH:** галочка **Install OpenSSH server**.
7. **Featured snaps — ничего не выбирай**: snap-версия docker несовместима с minikube.
8. После «Installation complete» нажми **Reboot Now**, затем Enter, если ВМ попросит извлечь диск.

---

## 5. Первая настройка ВМ

### 5.1. Подключение по SSH

PowerShell:

```powershell
ssh laloni@192.168.56.10
```

На вопрос о ключе ответь `yes`. Все дальнейшие команды без пометки «PowerShell» вводятся в этом окне.

В VS Code можно поставить расширение **Remote - SSH** → F1 → «Remote-SSH: Connect to Host» → `laloni@192.168.56.10`.

### 5.2. Обновление и пакеты

```bash
sudo apt update && sudo apt -y full-upgrade
```

```bash
sudo apt install -y git curl ca-certificates openssl unzip python3-venv python3-pip jq
```

### 5.3. Проверка диска и сети

```bash
df -h /
```

Размер должен быть около 58G. Если там около 29G, расширь раздел на весь диск:

```bash
sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
```

```bash
ip -4 addr show enp0s8
```

Должно быть `inet 192.168.56.10/24`.

```bash
ping -c 2 github.com
```

📌 **Снимок ВМ:** `sudo poweroff` → в VirtualBox: Снимки → Сделать снимок «01 чистая Ubuntu» → снова запусти ВМ и подключись по SSH.

---

## 6. Docker, kubectl, minikube

### 6.1. Docker Engine

```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

```bash
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
```

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
```

Вывод — одна строка, заканчивается на `noble stable`.

```bash
sudo apt update
```

В выводе должна быть строка с `download.docker.com`.

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
```

```bash
sudo usermod -aG docker $USER
```

```bash
exit
```

Подключись заново (`ssh laloni@192.168.56.10` в PowerShell) и проверь, что Docker работает без sudo:

```bash
docker run --rm hello-world
```

Ожидается «Hello from Docker!».

### 6.2. kubectl

```bash
curl -LO https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl
```

```bash
sudo install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl
```

### 6.3. minikube

```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
```

```bash
sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64
```

```bash
kubectl version --client && minikube version
```

> minikube и docker всегда запускай **без sudo**.

📌 Снимок «02 docker+minikube».

---

## 7. Проект и Python-окружение

### 7.1. Скопировать проект в ВМ

PowerShell (на Windows):

```powershell
scp "C:\Users\noize\Desktop\3 курс\Курсовая\wifi-guard.zip" laloni@192.168.56.10:~
```

В ВМ:

```bash
cd ~ && unzip -o wifi-guard.zip && ls ~/wifi-guard
```

*(Если проект уже лежит на GitHub: `git clone https://github.com/LaloniBley/Wifi-Guard.git ~/wifi-guard`.)*

### 7.2. Окружение

```bash
cd ~/wifi-guard && python3 -m venv .venv
```

```bash
echo 'source ~/wifi-guard/.venv/bin/activate' >> ~/.bashrc && source ~/.bashrc
```

В начале строки появится `(.venv)` — теперь окружение будет включаться автоматически при каждом входе.

```bash
pip install -r requirements-dev.txt ansible-core kubernetes
```

```bash
ansible-galaxy collection install -r ansible/requirements.yml
```

```bash
chmod +x scripts/*.sh
```

---

## 8. Проверка кода тестами (подраздел 3.1)

```bash
cd ~/wifi-guard && pytest -v
```

```bash
ruff check common services client tests
```

Ожидается `34 passed` и `All checks passed!`.

📸 **Скриншот 1:** последние строки `pytest -v` с `34 passed`.

---

## 9. Параметры развертывания

Ставим объём памяти для minikube (7168 или 8192 — из таблицы раздела 1) и IP ВМ для сертификата шлюза:

```bash
sed -i 's/^minikube_memory_mb: .*/minikube_memory_mb: 8192/' ~/wifi-guard/ansible/group_vars/all.yml
```

```bash
sed -i 's/^cert_extra_ips: .*/cert_extra_ips: "192.168.56.10"/' ~/wifi-guard/ansible/group_vars/all.yml
```

```bash
grep -E "^(minikube_cpus|minikube_memory_mb|cert_extra_ips)" ~/wifi-guard/ansible/group_vars/all.yml
```

Ожидается:

```
minikube_cpus: 4
minikube_memory_mb: 8192
cert_extra_ips: "192.168.56.10"
```

> `cert_extra_ips` задаётся **до** первого запуска плейбука: сертификаты выпускаются один раз.

---

## 10. Развертывание одной командой (подраздел 3.2)

```bash
cd ~/wifi-guard/ansible && ansible-playbook -i inventory.ini deploy.yml
```

Что делает плейбук:
1. запускает minikube (CNI Calico);
2. собирает 7 образов (`docker build`) и загружает их в кластер (`minikube image load`);
3. выпускает сертификаты и генерирует секреты;
4. создаёт пространства имён и секреты Kubernetes;
5. применяет манифесты;
6. ждёт Oracle и все микросервисы.

**Чего ожидать по времени (первый запуск — 40–60 минут):**

| Шаг | Время | Что видно на экране |
|---|---|---|
| Запустить minikube с CNI Calico | 5–15 мин | ничего, ждать |
| Собрать образы / Загрузить образы в кластер | 5–10 мин | по строке на каждый образ |
| Дождаться готовности СУБД Oracle | до 20 мин | ничего — качается образ ~1,5–2 ГБ и создаётся БД |
| Дождаться готовности микросервисов | 1–5 мин | `ok` по каждому сервису |

Пока плейбук молчит, во **втором окне SSH** можно смотреть, что происходит:

```bash
watch -n 5 kubectl get pods -A
```

Пока minikube запускается, здесь будут ошибки `connection refused` — это нормально, кластера ещё нет. Выход из `watch` — Ctrl+C.

В конце должно быть `PLAY RECAP ... failed=0` и сообщение «Итог развёртывания».

📸 **Скриншот 2:** `PLAY RECAP` и «Итог развёртывания».

> Если плейбук всё-таки упал на ожидании Oracle или сервисов: дождись, пока `kubectl get pods -A` покажет у
> всех подов `wg-*` READY `1/1` (у gateway `3/3`), и запусти плейбук ещё раз — это безопасно.

---

## 11. Проверка развертывания

### 11.1. Поды и пространства имён

```bash
kubectl get pods -A -l app.kubernetes.io/part-of=wifi-guard
```

Должно быть 9 подов, все `Running`, READY: `gateway` — `3/3`, остальные — `1/1`. Пара перезапусков (RESTARTS) у
`gateway` и сервисов с БД — норма: они стартовали раньше, чем был готов Oracle.

📸 **Скриншот 3.**

```bash
kubectl get ns -l app.kubernetes.io/part-of=wifi-guard --show-labels
```

### 11.2. Pod Security Admission

```bash
kubectl run evil -n wg-core --image=busybox:1.36 --privileged -- sleep 60
```

Ожидается отказ: `Error from server (Forbidden): pods "evil" is forbidden: violates PodSecurity "restricted:latest": privileged ..., allowPrivilegeEscalation ..., unrestricted capabilities ..., runAsNonRoot ..., seccompProfile ...`

📸 **Скриншот 4.**

### 11.3. Сетевые политики и изоляция

```bash
kubectl get networkpolicy -A
```

Должно быть 16 политик.

```bash
kubectl run nettest --rm -it --restart=Never --image=curlimages/curl:8.10.1 -- curl -sS -m 3 http://portal.wg-core.svc.cluster.local:8000/healthz
```

Ожидается `curl: (28) Connection timed out after 3001 milliseconds` — портал напрямую недоступен.

```bash
kubectl run nettest --rm -it --restart=Never --image=curlimages/curl:8.10.1 -- curl -sS -k -m 3 https://gateway.wg-edge.svc.cluster.local/healthz
```

Ожидается `{"status":"ok"}` — шлюз как единственная точка входа отвечает.

📸 **Скриншот 5:** обе команды.

### 11.4. Калибровка и сценарии атак

```bash
cd ~/wifi-guard && NODE=$(minikube -p wifi-guard ip) && echo $NODE
```

Калибровка эталона маршрута, **один раз**. Её делают оттуда, где работает легитимный клиент, — здесь это сама ВМ:

```bash
python client/client_sim.py --base https://$NODE:30443 --scenario calibrate
```

Ожидается:
```
POST /api/login -> 200
POST /api/admin/aps -> 201 {"bssid":"a0:b1:c2:d3:e4:01", ... "ref_hops":1, ...}
```

Сценарии:

```bash
clear; for s in normal rogue-ap evil-twin relay stolen-token; do echo "=== $s"; python client/client_sim.py --base https://$NODE:30443 --scenario $s; done
```

| Сценарий | Ожидаемый результат |
|---|---|
| normal | `/portal/profile -> 200`, `"verdict":"ALLOW"` |
| rogue-ap (С1) | `/api/login -> 403`, `BSSID_UNTRUSTED`, `TWIN_IN_AIR` |
| evil-twin (С1) | `/api/login -> 403`, `PMF_NOT_NEGOTIATED`, `TWIN_IN_AIR` |
| relay | `/portal/profile -> 200`, `"verdict":"SUSPICIOUS"` |
| stolen-token (С2) | `/portal/profile -> 401`, `"reason":"binding_mismatch"` |

📸 **Скриншот 6.**

### 11.5. Журнал аудита и метрики

```bash
kubectl -n wg-monitoring port-forward svc/audit 8004:8004 >/dev/null &
```

```bash
curl -s "http://127.0.0.1:8004/events?type=SECURITY_VERDICT&limit=5" | jq '.[] | {ts, verdict, score, scenario}'
```

```bash
curl -s http://127.0.0.1:8004/metrics | grep -E "^wg_(verdicts|indicators|auth_failures|sessions)"
```

📸 **Скриншот 7:** метрики `wg_*`.

```bash
kill %1
```

### 11.6. Grafana в браузере Windows

```bash
cat ~/wifi-guard/ansible/.secrets/grafana; echo
```

Это пароль пользователя `admin`. Запусти проброс порта (окно будет занято, пока он работает):

```bash
kubectl -n wg-monitoring port-forward --address 0.0.0.0 svc/grafana 3000:3000
```

В браузере на Windows открой `http://192.168.56.10:3000` и войди как `admin`. Затем Connections → Data sources → Prometheus → **Test**.
Ожидается «Successfully queried». Дашборды — в главе 4. В ВМ нажми Ctrl+C.

---

## 12. Доступ к шлюзу из Windows

Опубликуй шлюз на адресе ВМ (после **каждой** перезагрузки ВМ — заново):

```bash
cd ~/wifi-guard && ./scripts/expose-gateway.sh
```

Ожидается `Шлюз опубликован: https://192.168.56.10:8443`.

PowerShell (на Windows). Папка `wg` с актуальным `client_sim.py` уже есть.

```powershell
cd $HOME\wg
```

```powershell
scp -r laloni@192.168.56.10:~/wifi-guard/certs $HOME\wg\certs
```

```powershell
pip install httpx
```

```powershell
python client_sim.py --base https://192.168.56.10:8443 --scenario normal --ca certs\ca.crt --cert certs\user1.crt --key certs\user1.key
```

Ожидается `200` и вердикт **SUSPICIOUS**. Это правильно: с Windows маршрут на один узел длиннее, чем при калибровке
из ВМ, и срабатывает признак N1. Чтобы Windows считалась «своей» точкой подключения, откалибруй с неё
(тогда из ВМ будет SUSPICIOUS):

```powershell
python client_sim.py --base https://192.168.56.10:8443 --scenario calibrate --ca certs\ca.crt --admin-cert certs\admin1.crt --admin-key certs\admin1.key
```

> Симулятор подключается напрямую, в обход системного прокси Windows (VPN-клиенты), и работает на Python 3.12 и 3.13.

### Postman

1. Settings → **Proxy**: снять галочку «Use system proxy», иначе VPN-прокси оборвёт соединение.
2. Settings → Certificates → **CA certificates**: включить, выбрать файл `C:\Users\noize\wg\certs\ca.crt`.
3. **Add Certificate**: Host `192.168.56.10`, Port `8443`, PFX file `certs\user1.p12`, Passphrase `wifiguard`.
4. Значение заголовка телеметрии получи в ВМ:
   ```bash
   cd ~/wifi-guard && python -c "import sys; sys.path.insert(0,'client'); from client_sim import telemetry_for as t; print(t('normal'))"
   ```
5. Запрос `POST https://192.168.56.10:8443/api/login`:
   * Headers: `X-WG-Telemetry: <значение из п. 4>`;
   * Body → raw → JSON: `{"username":"ivanov","password":"Ivanov#2026"}`.
6. Запрос `GET https://192.168.56.10:8443/portal/profile` с заголовками `X-WG-Telemetry` и `Authorization: Bearer <access_token>`.

---

## 13. Публикация в GitHub

1. GitHub → аватар → Settings → Developer settings → **Personal access tokens → Tokens (classic)** → Generate.
   Права: `repo` и `workflow`. Скопируй токен.
2. В ВМ:

```bash
cd ~/wifi-guard && git init -b main
```

```bash
git config --global user.name "Nikita Vasilev" && git config --global user.email "lalonibley@gmail.com"
```

```bash
git add . && git status --short | grep -E "certs/|\.secrets/|\.venv/" || echo "секретов в коммите нет"
```

Должно быть «секретов в коммите нет».

```bash
git commit -m "WiFi-Guard: микросервисы, манифесты, Ansible, CI"
```

```bash
git remote add origin https://github.com/LaloniBley/Wifi-Guard.git
```

```bash
git push -u origin main
```

Логин — `LaloniBley`, пароль — **токен**. Если push отклонён, потому что в репозитории осталась старая версия,
выполни `git push -u origin main --force`: она заменит старую версию новой.

3. На GitHub: Settings → Actions → General → Workflow permissions → **Read and write permissions** → Save.
4. Вкладка **Actions**: у конвейера `ci` должны быть зелёные галочки на заданиях test, manifests и images.

📸 **Скриншот 8:** вкладка Actions.

---

## 14. Скриншоты для главы 3

| № | Что | Куда |
|---|---|---|
| 1 | `pytest -v` → 34 passed | конец 3.1 |
| 2 | `PLAY RECAP` плейбука | 3.2, «Автоматизация развертывания» |
| 3 | поды всех пространств имён | 3.2, «Пространства имён» |
| 4 | отказ PSA | 3.2, после таблицы 3 |
| 5 | тест изоляции | 3.2, после рисунка 15 |
| 6 | сценарии normal / С1 / С2 | конец 3.2 (или глава 4) |
| 7 | метрики `wg_*` | 3.2 (или глава 4) |
| 8 | GitHub Actions | 3.2, «Репозиторий и CI/CD» |

Перед скриншотом очисти экран (`clear`), чтобы в кадр попал только нужный вывод.

---

## 15. Повседневная работа

| Действие | Команды |
|---|---|
| Выключить | `minikube stop -p wifi-guard`, затем `sudo poweroff` |
| Включить | запустить ВМ → `ssh laloni@192.168.56.10` → `minikube start -p wifi-guard` → подождать 3–5 мин (`kubectl get pods -A`) → `cd ~/wifi-guard && ./scripts/expose-gateway.sh` |
| Обновить код после правок | `cd ~/wifi-guard/ansible && ansible-playbook -i inventory.ini deploy.yml`, затем `kubectl rollout restart deploy -n wg-core` |
| Удалить паттерн | `cd ~/wifi-guard/ansible && ansible-playbook -i inventory.ini teardown.yml` |
| Удалить кластер | `minikube delete -p wifi-guard` |

📌 Снимок «03 паттерн развёрнут» после раздела 11.

---

## 16. Задел для главы 4

ВМ «пользователь» (`192.168.56.20`) и «нарушитель» (`192.168.56.30`) создаются по разделам 3–5: 2 ГБ ОЗУ, 2 ЦП,
адаптер 2 — та же host-only сеть. Они обращаются к шлюзу `https://192.168.56.10:8443`, поэтому `expose-gateway.sh`
должен быть запущен. Калибровку из 11.4 повтори с ВМ «пользователь».

---

## 17. Если что-то пошло не так

| Симптом | Причина и решение |
|---|---|
| `: command not found`, `Package docker-ce has no installation candidate` | команда вставилась с разрывом строки — вставляй блоки по одному (раздел «Как пользоваться») |
| `permission denied ... docker.sock` | не перезашёл после `usermod`: `exit` и снова `ssh` |
| `kubectl ... localhost:8080 connection refused` | minikube ещё запускается — подожди |
| `RSRC_INSUFFICIENT_CONTAINER_MEMORY` | у ВМ мало ОЗУ для `minikube_memory_mb` — уменьши значение (раздел 9) или добавь ОЗУ ВМ |
| `oracle-0` долго `ContainerCreating` | качается образ ~1,5–2 ГБ — `kubectl -n wg-data get events -w`, ждать `Pulled` |
| `ErrImagePull` у `wifi-guard/...` | образы не загружены в кластер: `minikube -p wifi-guard image ls \| grep wifi-guard` (должно быть 7) — перезапусти плейбук |
| `client certificate required` у симулятора | старая версия `client_sim.py` — возьми из архива или папки «Курсовая» |
| `WinError 10054` на Windows | старая версия `client_sim.py` (шла через системный прокси) или не запущен `expose-gateway.sh` |
| `CA cert does not include key usage extension` | старая версия `client_sim.py` на Python 3.13 |
| Из Windows нет ответа на `:8443` | после перезагрузки ВМ не запущен `./scripts/expose-gateway.sh` |
| Портал отвечает в тесте изоляции | кластер без Calico — `minikube delete -p wifi-guard` и снова плейбук |
| `ansible-playbook: command not found` | не активировано окружение: `source ~/wifi-guard/.venv/bin/activate` |
| В Actions упало задание images: `denied` | раздел 13, п. 3 |
