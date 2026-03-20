# dnstt — enhanced fork

**dnstt** — DNS-туннель для TCP-трафика. Трафик кодируется внутри DNS-запросов
и ответов, проходя через публичный рекурсивный резолвер. Это позволяет
обходить блокировки, не требуя собственного VPN-протокола или специального
порта.

Форк оригинального [dnstt](https://www.bamsoftware.com/software/dnstt/) (David Fifield), расширенный новыми транспортами, встроенным SOCKS5-прокси,
аутентификацией, rate-limiting, TLS-маскировкой и операционным инструментарием.

```
┌──────────┐            ┌──────────────┐            ┌──────────┐
│  Client  │◄─DoH/DoT──►│  Recursive   │◄──UDP 53──►│  Server  │
│  (you)   │ /DoQ/UDP   │  Resolver    │            │  (yours) │
└────┬─────┘            └──────────────┘            └─────┬────┘
     │ TCP :7000                                          │ TCP
┌────┴─────┐                                        ┌─────┴────┐
│  Your    │                                        │ Upstream │
│  App     │                                        │ Service  │
└──────────┘                                        └──────────┘
```

Трафик вашего приложения → TCP → dnstt-client → DNS-запросы → резолвер → dnstt-server → TCP → целевой сервис.

---

## Содержание

1. [Как это работает](#как-это-работает)
2. [Стек технологий](#стек-технологий)
3. [DNS-зона: предварительная настройка](#dns-зона-предварительная-настройка)
4. [Сборка и запуск — сервер](#сборка-и-запуск--сервер)
5. [Сборка и запуск — клиент](#сборка-и-запуск--клиент)
6. [Развёртывание через Docker](#развёртывание-через-docker)
7. [Все флаги сервера](#все-флаги-сервера)
8. [Все флаги клиента](#все-флаги-клиента)
9. [Файл конфигурации](#файл-конфигурации)
10. [Шифрование и аутентификация](#шифрование-и-аутентификация)
11. [Примеры использования](#примеры-использования)

---

## Как это работает

DNS-туннель эксплуатирует свойство DNS: большинство сетей разрешают исходящие
DNS-запросы, в том числе через DoH/DoT (порт 443/853), чтобы обеспечить базовое
разрешение имён.

**Клиент** кодирует TCP-данные в поддомены зоны, делегированной серверу
(`<payload>.t.example.com`), и шлёт их запросами типа TXT. Ответ сервера
несёт данные в обратном направлении в TXT-записях.

**Сервер** запущен как авторитативный NS для выбранного поддомена,
принимает UDP-запросы от рекурсивного резолвера, декодирует данные и
форвардирует потоки TCP к целевому сервису.

**Стек поверх DNS:**

```
Ваше приложение (TCP)
      ↕
   smux v2        — мультиплексирование нескольких потоков в одном сеансе
      ↕
   Noise_NK       — E2E-шифрование и аутентификация сервера
      ↕
   KCP            — надёжная доставка поверх UDP-подобного канала
      ↕
DNS-сообщения (TXT/AAAA)
      ↕
DoH / DoT / DoQ / UDP
```

---

## Стек технологий

| Компонент | Библиотека | Назначение |
|---|---|---|
| **KCP** | `github.com/xtaci/kcp-go/v5` | Надёжная упорядоченная доставка поверх пакетного DNS-канала. Аналог TCP поверх UDP. Управляет повторными передачами, окном, перегрузкой |
| **smux** | `github.com/xtaci/smux` | Мультиплексор потоков (v2). Несколько TCP-соединений клиента объединяются в один KCP-сеанс, экономя handshake-overhead |
| **Noise_NK** | `github.com/flynn/noise` | Протокол Noise, паттерн NK: сервер аутентифицирован публичным ключом, клиент анонимен. Шифр: ChaChaPoly. Хэш: BLAKE2s. DH: X25519 |
| **DNS over QUIC** | `github.com/quic-go/quic-go` | RFC 9250. Каждый запрос — отдельный QUIC-стрим; 0-RTT там, где возможно |
| **DNS over TLS** | стандартная библиотека + uTLS | RFC 7858. Пайплайнинг: 8 одновременных отправителей на соединение |
| **DNS over HTTPS** | `net/http` + uTLS | RFC 8484. POST `application/dns-message`. Retry-After поддерживается |
| **uTLS** | `github.com/refraction-networking/utls` | Камуфляж TLS-fingerprint под браузер (Firefox, Chrome, iOS…), чтобы DoT/DoH-трафик не отличался от обычного браузерного |
| **FEC** | `github.com/klauspost/reedsolomon` (через kcp-go) | Reed-Solomon Forward Error Correction для восстановления потерянных пакетов без ретрансмиссии |
| **YAML-конфиг** | `gopkg.in/yaml.v3` | Конфигурационный файл сервера |
| **Криптография** | `golang.org/x/crypto` | X25519 DH, ChaCha20-Poly1305, BLAKE2s |
| **Сжатие** | `compress/zlib` (stdlib) | Опциональное сжатие потоков. Враппер `zlibFlushWriter` принудительно делает `Flush()` после каждой записи — без этого интерактивные сессии (SSH) зависали бы |
| **Метрики** | `expvar` (stdlib) | Счётчики запросов, сессий, dropped-пакетов на `/debug/vars` |
| **Профилировщик** | `net/http/pprof` (stdlib) | CPU/heap/goroutine профили на `/debug/pprof` |
| **Логирование** | `log/slog` (stdlib, Go 1.21+) | Структурированные логи с фильтрацией по уровню и UTC-временем |
| **SOCKS5** | собственная реализация | RFC 1928. Только CONNECT без аутентификации |

---

## DNS-зона: предварительная настройка

Сервер должен быть авторитативным NS для выбранного поддомена.
Пусть ваш домен — `example.com`, IP сервера — `203.0.113.2`.

Добавьте в DNS вашего домена:

```dns
; Глейу-запись для NS-сервера
tns.example.com.  A     203.0.113.2
tns.example.com.  AAAA  2001:db8::2    ; если есть IPv6

; Делегирование зоны туннеля
t.example.com.    NS    tns.example.com.
```

Проверка (после распространения записей):

```sh
dig NS t.example.com
# ожидаем: tns.example.com

dig TXT anything.t.example.com @203.0.113.2
# если сервер уже запущен — ответит
```

> **Важно:** держите метку зоны (`t`) короткой. DNS-имена ограничены 255 байтами;
> чем длиннее домен, тем меньше полезной нагрузки в каждом запросе.

---

## Сборка и запуск — сервер

### Требования

- Go 1.24 или новее
- Права на порт UDP 53 (либо iptables REDIRECT с непривилегированного порта)

### Сборка

```sh
git clone https://github.com/IvanTopGaming/dnstt
cd dnstt

# Сборка сервера
go build -o dnstt-server ./dnstt-server

# Сборка клиента
go build -o dnstt-client ./dnstt-client
```

Или оба сразу:

```sh
go build ./...
# бинарники появятся в dnstt-server/ и dnstt-client/
```

### Генерация ключей

```sh
./dnstt-server/dnstt-server -gen-key \
    -privkey-file server.key \
    -pubkey-file  server.pub

# Или без файлов — ключи выводятся в stdout
./dnstt-server/dnstt-server -gen-key
# privkey 0123456789abcdef0123...
# pubkey  fedcba9876543210fedc...
```

`server.key` (приватный) — только на сервере, режим 0400.
`server.pub` (публичный) — передать клиентам, не секрет.

### Запуск: встроенный SOCKS5-прокси (рекомендуется)

```sh
./dnstt-server/dnstt-server \
    -udp :53 \
    -privkey-file server.key \
    -socks5 \
    t.example.com
```

В этом режиме клиент сам указывает куда подключаться (через SOCKS5-запрос).
Отдельный прокси-сервис не нужен.

### Запуск: форвардинг к конкретному сервису

```sh
# Форвардинг к SSH
./dnstt-server/dnstt-server \
    -udp :53 \
    -privkey-file server.key \
    t.example.com 127.0.0.1:22

# Форвардинг к HTTP-прокси
./dnstt-server/dnstt-server \
    -udp :53 \
    -privkey-file server.key \
    t.example.com 127.0.0.1:3128
```

### Порт 53 без root

```sh
# Запуск на непривилегированном порту
./dnstt-server/dnstt-server -udp :5353 -privkey-file server.key -socks5 t.example.com

# Перенаправление порта 53 → 5353
sudo iptables  -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
sudo ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
```

### Запуск через systemd

Создайте `/etc/systemd/system/dnstt-server.service`:

```ini
[Unit]
Description=dnstt DNS tunnel server
After=network.target

[Service]
ExecStart=/usr/local/bin/dnstt-server \
    -udp :53 \
    -privkey-file /etc/dnstt/server.key \
    -socks5 \
    -log-level info \
    t.example.com
Restart=on-failure
RestartSec=5
User=nobody
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now dnstt-server
sudo journalctl -u dnstt-server -f
```

---

## Сборка и запуск — клиент

### Сборка

```sh
go build -o dnstt-client ./dnstt-client
```

### Выбор транспорта

| Транспорт | Флаг | Скрытность | Скорость | Когда использовать |
|---|---|---|---|---|
| DNS over QUIC | `-doq resolver:853` | Высокая | Высокая | Современные резолверы, QUIC не заблокирован |
| DNS over TLS | `-dot resolver:853` | Высокая | Средняя | Универсальный выбор |
| DNS over HTTPS | `-doh https://…/dns-query` | Высокая | Средняя | Через HTTP-прокси, порт 443 |
| UDP | `-udp resolver:53` | Нет | Средняя | Только для отладки |
| Авто | `-auto` + адреса | — | — | Пробует DoQ→DoT→DoH→UDP |
| Мультипуть | `-multipath` | Высокая | Высокая | Одновременно несколько транспортов |

Публичные резолверы:
- **Cloudflare:** `1.1.1.1:853` (DoT/DoQ), `https://1.1.1.1/dns-query` (DoH)
- **Google:** `8.8.8.8:853` (DoT), `https://dns.google/dns-query` (DoH)
- **Quad9:** `9.9.9.9:853` (DoT/DoQ), `https://dns.quad9.net/dns-query` (DoH)

### Запуск

```sh
# DNS over QUIC
./dnstt-client -doq 1.1.1.1:853 \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000

# DNS over TLS
./dnstt-client -dot 1.1.1.1:853 \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000

# DNS over HTTPS
./dnstt-client -doh https://1.1.1.1/dns-query \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000

# Авто — пробует DoQ, затем DoT, затем DoH
./dnstt-client -auto \
    -doq 1.1.1.1:853 \
    -dot 1.1.1.1:853 \
    -doh https://1.1.1.1/dns-query \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000
```

После запуска клиент слушает TCP на `127.0.0.1:7000`. Настройте своё
приложение на этот адрес как SOCKS5-прокси (если сервер в `-socks5` режиме)
или как обычный TCP-форвард.

```sh
# Проверка: HTTP через SOCKS5
curl --proxy socks5h://127.0.0.1:7000/ https://example.com/

# Проверка: SSH через форвард
ssh -p 7000 user@127.0.0.1
```

---

## Развёртывание через Docker

### Предварительные требования

- Docker Engine 24+ и Docker Compose v2
- Порт UDP 53 свободен на хосте

### Быстрый старт

**Шаг 1.** Создайте файл `.env` с именем вашей зоны:

```sh
echo "DNSTT_DOMAIN=t.example.com" > .env
```

**Шаг 2.** Сгенерируйте ключи (записываются в `./keys/`):

```sh
docker compose run --rm keygen
```

Проверьте:
```sh
ls -la keys/
# server.key (0400)  server.pub
```

**Шаг 3.** Запустите сервер:

```sh
docker compose up -d
docker compose logs -f
```

**Шаг 4.** Скопируйте `keys/server.pub` на клиентские машины.

### Структура образа

```dockerfile
# Этап 1: сборка
FROM golang:1.24-alpine AS builder
# компилирует dnstt-server с CGO_ENABLED=0 и -trimpath

# Этап 2: итоговый образ
FROM scratch AS server
# только бинарник, без ОС, без shell, без пакетного менеджера
# пользователь: nobody (uid 65534)
# возможности: только NET_BIND_SERVICE (привязка порта 53)
```

Итоговый образ весит ~7 МБ.

### Конфигурация docker-compose.yml

По умолчанию сервер запускается в режиме `-socks5`.
Чтобы форвардировать к конкретному сервису, отредактируйте `command:`:

```yaml
# docker-compose.yml

services:
  dnstt-server:
    build:
      context: .
      target: server
    restart: unless-stopped
    ports:
      - "53:53/udp"
    volumes:
      - ./keys:/keys:ro
    user: "65534:65534"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    command:
      - -udp
      - ":53"
      - -privkey-file
      - /keys/server.key
      # Режим SOCKS5 (клиент выбирает куда подключаться):
      - -socks5
      - "${DNSTT_DOMAIN}"
      # Или форвардинг к конкретному адресу (убрать -socks5):
      # - 127.0.0.1:8000
```

### Дополнительные флаги в Docker

Добавьте нужные флаги в `command:` — каждый флаг и его значение
как отдельная строка YAML:

```yaml
command:
  - -udp
  - ":53"
  - -privkey-file
  - /keys/server.key
  - -socks5
  - -rate-limit
  - "20"
  - -rate-burst
  - "100"
  - -log-level
  - debug
  - -paranoia
  - "${DNSTT_DOMAIN}"
```

### Полезные команды

```sh
# Запустить в фоне
docker compose up -d

# Посмотреть логи
docker compose logs -f dnstt-server

# Перегенерировать ключи (осторожно: клиенты нужно перенастроить)
docker compose run --rm keygen

# Остановить
docker compose down

# Пересобрать образ после изменений кода
docker compose build --no-cache
docker compose up -d
```

### Сборка образа вручную

```sh
# Собрать образ
docker build --target server -t dnstt-server:latest .

# Запустить
docker run -d \
  --name dnstt \
  -p 53:53/udp \
  -v $(pwd)/keys:/keys:ro \
  --user 65534:65534 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  dnstt-server:latest \
    -udp :53 \
    -privkey-file /keys/server.key \
    -socks5 \
    t.example.com
```

---

## Все флаги сервера

### Режим генерации ключей

```
dnstt-server -gen-key [-privkey-file FILE] [-pubkey-file FILE]
```

| Флаг | Описание |
|---|---|
| `-gen-key` | Сгенерировать пару ключей и выйти. Без `-privkey-file`/`-pubkey-file` выводит hex-строки в stdout |
| `-privkey-file FILE` | С `-gen-key`: сохранить приватный ключ в файл (режим 0400). В рабочем режиме: прочитать ключ из файла |
| `-pubkey-file FILE` | С `-gen-key`: сохранить публичный ключ в файл. В рабочем режиме не используется |

### Рабочий режим

```
dnstt-server -udp ADDR [-privkey-file FILE | -privkey HEX] [OPTIONS] DOMAIN [UPSTREAM]
```

#### Обязательные

| Флаг | Описание |
|---|---|
| `-udp ADDR` | UDP-адрес для приёма DNS-запросов. Обычно `:53`. Без этого флага сервер не запустится |
| `DOMAIN` | Корень DNS-зоны туннеля (`t.example.com`). Позиционный аргумент |
| `UPSTREAM` | TCP-адрес для форвардинга потоков (`127.0.0.1:8000`). Позиционный аргумент. Не используется с `-socks5` |

#### Ключи

| Флаг | Описание |
|---|---|
| `-privkey HEX` | Приватный ключ как строка из 64 hex-символов |
| `-privkey-file FILE` | Читать приватный ключ из файла. Если ни `-privkey`, ни `-privkey-file` не заданы, сервер генерирует временный ключ и логирует публичный |

#### Режим работы

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-socks5` | `false` | Встроенный SOCKS5-прокси. Каждый поток выполняет SOCKS5-handshake, сервер подключается к адресу, указанному клиентом. При использовании `UPSTREAM` не нужен |
| `-mtu N` | `1232` | Максимальный размер UDP-ответа в байтах. Уменьшайте, если резолвер жалуется: `FORMERR: requester payload size 512 is too small` |
| `-paranoia` | `false` | Возвращать правдоподобные поддельные A/AAAA-ответы на нетуннельные запросы, скрывая факт наличия туннеля от пассивного наблюдателя |

#### Аутентификация

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-auth-keys FILE` | — | Файл авторизованных токенов: по одному 64-символьному hex-токену на строку. Клиент должен предъявить совпадающий токен (`-auth-token`) после Noise-handshake. Если флаг не задан — все клиенты принимаются |

#### Производительность

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-kcp-mode MODE` | `normal` | Режим KCP: `fast` (низкая задержка, больше трафика), `normal` (баланс), `slow` (экономия полосы) |
| `-fec-data N` | `0` | Количество шардов данных для Reed-Solomon FEC. `0` — отключено. Требует согласования с клиентом |
| `-fec-parity N` | `0` | Количество шардов чётности FEC. При N data и M parity — теряемо до M пакетов из каждого блока |
| `-compress` | `false` | Сжимать данные потоков (zlib). Должно совпадать с клиентом |
| `-rate-limit RATE` | `0` | Максимум DNS-запросов в секунду на клиента (token bucket). `0` — без ограничений |
| `-rate-burst N` | `50` | Размер всплеска для `-rate-limit`. Позволяет кратковременно превышать лимит |

#### Операционные

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-config FILE` | — | Загрузить значения флагов из YAML-файла до разбора аргументов командной строки. CLI-флаги перекрывают файл |
| `-debug-addr ADDR` | — | HTTP-сервер с `/debug/vars` (счётчики) и `/debug/pprof` (профили). Не открывать публично |
| `-log-level LEVEL` | `info` | Минимальный уровень логирования: `debug`, `info`, `warn`, `error` |

---

## Все флаги клиента

```
dnstt-client [-doh URL|-dot ADDR|-doq ADDR|-udp ADDR|-auto] \
             -pubkey-file FILE \
             [OPTIONS] \
             DOMAIN LOCALADDR
```

| Флаг | Позиционный аргумент |
|---|---|
| `DOMAIN` | DNS-зона туннеля (`t.example.com`) |
| `LOCALADDR` | TCP-адрес для прослушивания локальных подключений (`127.0.0.1:7000`) |

#### Транспорт

| Флаг | Описание |
|---|---|
| `-doh URL` | DNS over HTTPS. URL резолвера с путём (`https://1.1.1.1/dns-query`) |
| `-doh-addr ADDR:PORT` | Переопределить адрес для dial в DoH. SNI берётся из URL. Полезно при cert-pinning или когда DNS недоступен |
| `-dot ADDR:PORT` | DNS over TLS (RFC 7858). Стандартный порт 853 |
| `-doq ADDR:PORT` | DNS over QUIC (RFC 9250). Стандартный порт 853 |
| `-udp ADDR:PORT` | Обычный DNS over UDP. Только для отладки — нет скрытности |
| `-auto` | Автовыбор: пробует DoQ→DoT→DoH→UDP, использует первый работающий. Требует хотя бы одного из флагов выше |
| `-multipath` | Отправлять данные через все указанные транспорты одновременно (DoH+DoT+UDP). Повышает надёжность и пропускную способность. DoQ не поддерживается в мультипуть-режиме. Требует минимум два транспорта |

#### Ключи

| Флаг | Описание |
|---|---|
| `-pubkey HEX` | Публичный ключ сервера как 64 hex-символа |
| `-pubkey-file FILE` | Читать публичный ключ из файла |

#### Безопасность и маскировка

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-utls SPEC` | `4*random,3*Firefox_120,...` | Выбрать TLS-fingerprint из взвешенного распределения. Маскирует DoH/DoT-подключения под браузерный трафик. `none` — отключить uTLS. `random` — случайный fingerprint каждый раз. Формат: `3*Firefox,2*Chrome,1*iOS` |
| `-pin-cert PINS` | — | Comma-separated SHA256-пины сертификатов (`SHA256:aabbcc…`). Принимать только сертификаты с совпадающим fingerprint. Применяется к DoT/DoH/DoQ |
| `-obfuscate` | `false` | Вставлять случайные AAAA/A-запросы (~20%) между туннельными TXT-запросами. Делает паттерн трафика менее характерным |
| `-rotate-id N` | `0` | Обновлять ClientID каждые N минут. Меняет идентификатор туннельного сеанса, затрудняя долгосрочную корреляцию. `0` — отключено |
| `-auth-token HEX` | — | 64-символьный hex-токен для аутентификации на сервере. Должен совпадать с одной из записей в серверном `-auth-keys` |

#### Производительность

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-kcp-mode MODE` | `normal` | Режим KCP: `fast`, `normal`, `slow`. Должен совпадать с сервером |
| `-fec-data N` | `0` | FEC data shards. `0` — отключено |
| `-fec-parity N` | `0` | FEC parity shards |
| `-compress` | `false` | Сжатие потоков (zlib). Должно совпадать с сервером |

#### Операционные

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-config FILE` | — | Загрузить флаги из файла `key = value` до разбора аргументов |
| `-debug-addr ADDR` | — | HTTP-сервер с `/debug/vars` и `/debug/pprof` |
| `-log-level LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

---

## Файл конфигурации

### Сервер — YAML

Флаг `-config FILE` указывает YAML-файл. CLI-флаги всегда перекрывают файл.

**Полный пример `server.yaml`:**

```yaml
# server.yaml — конфигурация dnstt-server

# Сеть
udp: ":53"             # UDP-адрес для DNS-запросов
mtu: 1232              # максимальный размер UDP-ответа

# Ключ (один из двух вариантов)
privkey-file: /etc/dnstt/server.key
# privkey: "0123456789abcdef..."  # или напрямую hex-строка

# Режим работы
socks5: true           # встроенный SOCKS5-прокси
# Если socks5: false — DOMAIN и UPSTREAM передаются позиционно в CLI

# Безопасность
paranoia: false        # поддельные ответы для нетуннельных запросов
auth-keys: /etc/dnstt/tokens.txt  # файл авторизованных токенов

# Rate limiting
rate-limit: 20.0       # запросов/сек на клиента (0 = без ограничений)
rate-burst: 100        # всплеск

# Производительность
kcp-mode: normal       # fast | normal | slow
fec-data: 0            # Reed-Solomon data shards (0 = выключено)
fec-parity: 0          # Reed-Solomon parity shards
compress: false        # zlib-сжатие потоков

# Операционные
debug-addr: ""         # "127.0.0.1:6060" для включения
log-level: info        # debug | info | warn | error
```

Запуск с файлом:
```sh
./dnstt-server -config server.yaml t.example.com
```

Минимальный файл (SOCKS5-режим):
```yaml
udp: ":53"
privkey-file: /etc/dnstt/server.key
socks5: true
log-level: info
```

### Клиент — key=value

Флаг `-config FILE` указывает файл формата `ключ = значение`, по одному на строку.
Комментарии начинаются с `#`.

**Полный пример `client.conf`:**

```ini
# client.conf — конфигурация dnstt-client

# Транспорт (один из: doh, dot, doq, udp; или auto=true с несколькими)
dot = 1.1.1.1:853
# doh = https://1.1.1.1/dns-query
# doh-addr = 1.1.1.1:443      # переопределить IP для DoH
# doq = 1.1.1.1:853
# udp = 1.1.1.1:53
# auto = true                  # попробовать все по порядку
# multipath = true             # все транспорты одновременно

# Ключ сервера
pubkey-file = /etc/dnstt/server.pub
# pubkey = fedcba9876543210...  # или hex-строка

# Аутентификация
# auth-token = aabbcc...64hexchars...  # если сервер требует токен

# TLS-маскировка (для DoT/DoH)
utls = 4*random,3*Firefox_120,1*Chrome_120  # по умолчанию

# Безопасность
# pin-cert = SHA256:aabbccddeeff...  # пин сертификата резолвера
obfuscate = true            # случайные AAAA/A-запросы-приманки
rotate-id = 30              # обновлять ClientID каждые 30 минут

# Производительность
kcp-mode = normal           # fast | normal | slow
# fec-data = 4
# fec-parity = 2
# compress = false

# Операционные
log-level = info
# debug-addr = 127.0.0.1:6060
```

Запуск с файлом:
```sh
./dnstt-client -config client.conf t.example.com 127.0.0.1:7000
```

### Файл авторизованных токенов (сервер)

Файл для `-auth-keys` содержит по одному токену на строку.
Пустые строки и строки начинающиеся с `#` игнорируются.

**Генерация токенов:**
```sh
# Linux/macOS
openssl rand -hex 32

# или через Go
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Пример `tokens.txt`:**
```
# Авторизованные клиенты dnstt
# Формат: 64 hex-символа (32 байта)

a3f1c2e4d5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2
deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
```

Клиент использует токен:
```sh
./dnstt-client -auth-token a3f1c2e4d5b6a7f8... \
    -dot 1.1.1.1:853 -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000
```

---

## Шифрование и аутентификация

### Noise_NK_25519_ChaChaPoly_BLAKE2s

Туннель использует криптографический протокол
[Noise](https://noiseprotocol.org/), паттерн NK:

- **N** — клиент анонимен (ephemeral-only)
- **K** — сервер аутентифицирован заранее известным публичным ключом

| Примитив | Алгоритм | Назначение |
|---|---|---|
| DH | X25519 | Обмен ключами Диффи–Хеллмана |
| Шифр | ChaCha20-Poly1305 (AEAD) | Шифрование и целостность данных |
| Хэш | BLAKE2s | Вывод ключей, MAC |

Это означает:
- Содержимое туннеля **зашифровано и защищено от подмены** end-to-end
- Сервер **аутентифицирован**: клиент проверяет, что подключается к серверу
  с правильным ключом, а не к MitM
- Клиент **анонимен**: сервер не знает, кто именно подключается
  (если не используется `-auth-keys`)
- Шифрование **независимо от DoH/DoT/DoQ**: даже если транспортный уровень
  скомпрометирован, содержимое туннеля остаётся защищённым

### Управление ключами

```sh
# Сгенерировать и сохранить в файлы
./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub

# Только вывод в stdout (для ручного распределения)
./dnstt-server -gen-key
# privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# pubkey  fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210

# Использовать ключ напрямую (без файла)
./dnstt-server -privkey 0123...abcdef t.example.com 127.0.0.1:8000
./dnstt-client -pubkey fedcba...3210 -dot 1.1.1.1:853 t.example.com 127.0.0.1:7000
```

Если сервер запускается без ключа, он автоматически генерирует временный и
логирует публичный ключ. Клиентов нужно перенастраивать при каждом перезапуске.

---

## Примеры использования

### SSH-туннель через DNS

```sh
# Сервер: форвардинг к SSH
./dnstt-server -udp :53 -privkey-file server.key t.example.com 127.0.0.1:22

# Клиент: поднять туннель
./dnstt-client -dot 1.1.1.1:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

# Подключиться по SSH через туннель
ssh -p 7000 user@127.0.0.1
```

### SOCKS5 для браузера

```sh
# Сервер
./dnstt-server -udp :53 -privkey-file server.key -socks5 t.example.com

# Клиент
./dnstt-client -dot 1.1.1.1:853 -pubkey-file server.pub t.example.com 127.0.0.1:7000

# Использование
curl --proxy socks5h://127.0.0.1:7000/ https://ifconfig.me/
# В браузере: прокси SOCKS5 → 127.0.0.1:7000
```

### Максимальная скрытность

```sh
# Клиент с максимальной маскировкой
./dnstt-client \
    -auto \
    -doq 1.1.1.1:853 \
    -dot 1.1.1.1:853 \
    -doh https://1.1.1.1/dns-query \
    -utls '3*Firefox_120,2*Chrome_120,1*iOS_14' \
    -obfuscate \
    -rotate-id 15 \
    -pin-cert SHA256:$(openssl s_client -connect 1.1.1.1:853 </dev/null 2>/dev/null | \
        openssl x509 -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':') \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000
```

### Аутентификация клиентов

```sh
# Генерация токена
TOKEN=$(openssl rand -hex 32)
echo $TOKEN >> /etc/dnstt/tokens.txt

# Сервер с аутентификацией
./dnstt-server -udp :53 -privkey-file server.key \
    -auth-keys /etc/dnstt/tokens.txt \
    -socks5 t.example.com

# Клиент с токеном
./dnstt-client -dot 1.1.1.1:853 \
    -auth-token $TOKEN \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000
```

### Высокая надёжность (FEC + мультипуть)

```sh
# Сервер с FEC
./dnstt-server -udp :53 -privkey-file server.key \
    -fec-data 4 -fec-parity 2 \
    -kcp-mode fast \
    -socks5 t.example.com

# Клиент с мультипутём и FEC
./dnstt-client \
    -multipath \
    -doh https://1.1.1.1/dns-query \
    -dot 1.1.1.1:853 \
    -fec-data 4 -fec-parity 2 \
    -kcp-mode fast \
    -pubkey-file server.pub \
    t.example.com 127.0.0.1:7000
```

---

## Отладка

### Эффективная пропускная способность

При запуске оба бинарника логируют `effective MTU N` — полезная нагрузка
в байтах на один DNS-запрос/ответ. Чем короче домен, тем больше MTU.

Типичные значения:
- Клиент (запросы): 100–200 байт на запрос
- Сервер (ответы): 900–1100 байт на ответ

### Debug HTTP-сервер

```sh
# Запустить с debug-сервером
./dnstt-server -debug-addr 127.0.0.1:6060 ...

# Счётчики (запросы, сессии, dropped-пакеты)
curl http://127.0.0.1:6060/debug/vars | jq .

# CPU-профиль (30 секунд)
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30

# Горутины
curl http://127.0.0.1:6060/debug/pprof/goroutine?debug=1
```

### Подробные логи

```sh
./dnstt-server -log-level debug ...
./dnstt-client -log-level debug ...
```

---

## Credits

Оригинальный проект: [dnstt](https://www.bamsoftware.com/software/dnstt/)
by David Fifield — public domain.

Данный форк добавляет DoQ, SOCKS5, rate limiting, аутентификацию,
обфускацию, cert pinning, ClientID rotation, пайплайнинг, FEC, мультипуть,
Docker-поддержку и исправляет ряд багов. Все дополнения также
выпускаются в public domain.
