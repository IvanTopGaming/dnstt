# G3 — скрытность / detection (дизайн)

**Дата:** 2026-04-29
**Ветка:** `fix/audit-pass-1`
**Статус:** утверждено пользователем
**Покрывает:** дефекты #6, #8, #9 из аудита 2026-04-29

## Контекст

Аудит выявил три класса детектируемого поведения, которые позволяют пассивному DPI и активному prober'у отличить наш сервер/клиент от обычного DNS-трафика:

- **#6** — `paranoia` режим возвращает NXDOMAIN на не-A/AAAA запросы и Cloudflare-IPs из жёстко зашитого набора, без SOA в Authority. Один взгляд на `dig` и палево.
- **#8** — клиентский `obfuscate` шлёт decoy-запросы с 8 случайными буквами + ограниченный TLD-набор (`xkqzwbnp.com`), что выглядит как DGA-ботнет, а не как маскировка.
- **#9** — AAAA-blend-poll возвращает фиксированный `::` (16 нулевых байт), что недостижимо для реального авторитативного NS.

Совместимость не держим: `-paranoia` и `-obfuscate` флаги исчезают вместе с устаревшим поведением.

## Модель угроз

Защищаемся одновременно от:

- **A — пассивный bulk-DPI / SNI-инспектор / IDS / резолвер-аудит логов.** Видит трафик в потоке без активных действий. Ловит характерные паттерны (DGA-имена, странные ответы).
- **B — активный probing observer.** Подозревает зону → сам шлёт MX/NS/SOA/A/AAAA и проверяет, выглядит ли ответ как от настоящего auth NS.

C (полный сетевой adversary с traffic-correlation) — out of scope.

## Цели

1. Сервер ведёт себя как корректный авторитативный NS для своей зоны (SOA/NS в апексе, NXDOMAIN с SOA в Authority для несуществующих имён, REFUSED для запросов вне зоны).
2. AAAA-blend-poll маскируется под «нет AAAA-записи у этого имени» (NOERROR + пустой Answer + SOA в Authority), а не возвращает анти-realистичный `::`.
3. Клиент перестаёт генерировать DGA-подобные decoy-запросы.
4. Поведение auth-NS-mimicry — **дефолт**, а не opt-in флаг.

## Не цели

- Полная имитация продакшен-NS (AXFR refusal, NSID, EDNS-padding). Out of scope для этого аудит-прохода.
- Защита от resolver-уровневой fingerprinting'и (резолвер всё равно видит наши TXT-запросы к редкой зоне; этот канал утечки информации остаётся).
- Decoys для UDP-режима. UDP-режим документирован как «только для отладки», добавлять туда поддержку реалистичных decoy-доменов — overengineering.

## Архитектура

```
DNS query → recvLoop → responseFor(query, zone) → response

zone (zoneInfo) живёт всё время работы сервера, создаётся один раз
при старте на основе positional arg domain.

Внутри responseFor:

  ├─ Question.Name НЕ под zone.apex
  │    → REFUSED (AA=0)
  │
  ├─ Question.Name == zone.apex
  │    └─ switch QTYPE:
  │        case SOA:  Answer=[zone.soa],  AA=1
  │        case NS:   Answer=[zone.ns],   AA=1
  │        default:   Answer=nil, Authority=[zone.soa], AA=1, NOERROR
  │
  └─ Question.Name strictly under zone.apex
       └─ extract base32 prefix, decode
            ├─ decode error / payload too short → NXDOMAIN + Authority=[SOA], AA=1
            └─ payload OK with ClientID:
                 case TXT:  carry tunnel data; AA=1; payload to KCP
                 case AAAA: blend-in poll: Answer=nil, Authority=[zone.soa], AA=1, NOERROR
                 default:   NXDOMAIN + Authority=[SOA], AA=1
```

### Ключевые принципы

- **Apex поведение = «реальный NS».** SOA/NS-запросы возвращают синтезированные записи. A/AAAA/MX/прочее — корректный NOERROR с пустым Answer и SOA в Authority (стандартное поведение BIND/Knot для имени, у которого нет данных конкретного типа).

- **NXDOMAIN всегда несёт SOA в Authority.** Это закрывает прямую сигнатуру «non-existent-name → empty authority section», которая отличает наш текущий сервер от любого нормального NS.

- **Outside-zone = REFUSED.** Сейчас на любой запрос вне нашей зоны мы (или paranoia, или NXDOMAIN) — оба варианта неправильные. REFUSED — это то, что отвечает любой нормальный auth NS, у которого нет полномочий на запрашиваемое имя.

- **AAAA-blend = «нет AAAA-записи».** Совпадает с поведением auth NS для существующего имени без AAAA. Сохраняет туннель-функционал (данные в QNAME), убирает аномальный `::`.

## Компоненты

### Новый файл `dnstt-server/zone.go`

```go
type zoneInfo struct {
    apex dns.Name   // например t.ivantopgaming.ru
    soa  dns.RR     // synthesized SOA с RDATA готовым к передаче
    ns   dns.RR     // synthesized NS-record
}

func newZoneInfo(apex dns.Name) zoneInfo
```

**SOA значения (зашитые):**
- `mname` = `ns.<apex>` (полный DNS-name)
- `rname` = `hostmaster.<apex>`
- `serial` = `YYYYMMDD01` (на основе времени старта сервера; если `> 0xFFFFFFFF` — clamp)
- `refresh` = 3600
- `retry` = 1800
- `expire` = 604800
- `minimum` = 60

**NS значение:**
- target = `mname` = `ns.<apex>`

**TTL:** 60 (`responseTTL` константа из существующего main.go).

### Изменения в `dnstt-server/main.go`

**Сигнатуры:**
- `responseFor(query *dns.Message, zone zoneInfo) (*dns.Message, []byte)` — было `(query, domain, paranoia)`.
- `recvLoop(...)` — теряет `paranoia bool`, получает `zone zoneInfo`.
- `run(...)` — теряет `paranoia bool`, получает `zone zoneInfo`.

**Логика:**
- Тело `responseFor` переписывается по схеме из «Архитектуры».
- Функция `paranoidResponse` удаляется полностью.
- `sendLoop` AAAA-branch перестаёт класть `[16]byte{0}` в Answer; теперь Answer уже nil + Authority=[SOA] (заполнено в `responseFor`), `sendLoop` пропускает заполнение.
- Truncate-helper `rebuildAsTruncated` (из G1 task 8) теперь сохраняет также `Authority` section на первой попытке (drop при fallback вместе с Additional).

**main():**
- Убираем флаг `-paranoia` и переменную.
- Строим `zone := newZoneInfo(domain)` после парсинга positional arg.
- Передаём `zone` в `run` (вместо `paranoia`).

**dnstt-server/config.go:**
- Удаляем поле `Paranoia bool` из `ServerConfig`.
- Удаляем `setDefault("paranoia", ...)` из `applyServerConfig`.

### Изменения в `dnstt-client/main.go` и `dns.go`

**`dns.go`:**
- Удаляем функцию `sendDecoy` целиком (~50 строк).
- Удаляем вызов в `sendLoop`.
- Удаляем поле `obfuscate bool` из структуры `DNSPacketConn`.
- Удаляем параметр `obfuscate bool` из `NewDNSPacketConn`.
- Удаляем константу `decoyProbability`.

**`main.go`:**
- Удаляем флаг `-obfuscate` и переменную.
- Убираем `obfuscate` из 5 вызовов `NewDNSPacketConn` (multipath/multipath-reconnect/auto/single/single-reconnect).

**`start-client.sh`:**
- Удаляем строку `-obfuscate`.

**`dnstt-client/config.go`:** изменений не требуется — это `key=value` файл, при попытке указать `obfuscate = true` `flag.Set` упадёт с понятной ошибкой "no such flag", что нормально.

## Поток данных и edge cases

### Туннельный путь (TXT, со стороны сервера)

Без изменений. Логика base32-decode, ClientID extraction, payload→KCP остаётся как есть.

### AAAA-blend-poll

```
Client: dig random-base32-prefix.t.example.com AAAA
                           ↓
Server: responseFor sees:
  - name strictly under apex
  - prefix decodes OK
  - payload contains ClientID
  - QTYPE = AAAA
                           ↓
Response: NOERROR, AA=1, Question echoed,
          Answer = [], Authority = [zone.soa]
```

Клиент по-прежнему отправляет туннель-данные через QNAME (это работает); сервер не передаёт payload в AAAA-ответе (как и сейчас, по соображениям RRset-reordering на стороне резолвера).

### Active prober пробует non-tunnel запрос

```
$ dig @150.241.94.29 nonexistent.t.ivantopgaming.ru A
;; status: NXDOMAIN, AA=1
;; AUTHORITY SECTION:
t.ivantopgaming.ru.  60  IN  SOA  ns.t.ivantopgaming.ru. hostmaster.t.ivantopgaming.ru. 2026042901 3600 1800 604800 60

$ dig @150.241.94.29 t.ivantopgaming.ru SOA
;; status: NOERROR, AA=1
;; ANSWER SECTION:
t.ivantopgaming.ru.  60  IN  SOA  ns.t.ivantopgaming.ru. hostmaster.t.ivantopgaming.ru. 2026042901 3600 1800 604800 60

$ dig @150.241.94.29 t.ivantopgaming.ru NS
;; status: NOERROR, AA=1
;; ANSWER SECTION:
t.ivantopgaming.ru.  60  IN  NS  ns.t.ivantopgaming.ru.

$ dig @150.241.94.29 google.com A
;; status: REFUSED, AA=0

$ dig @150.241.94.29 t.ivantopgaming.ru MX
;; status: NOERROR, AA=1
;; ANSWER SECTION: (empty)
;; AUTHORITY SECTION:
t.ivantopgaming.ru.  60  IN  SOA  ns.t.ivantopgaming.ru. hostmaster.t.ivantopgaming.ru. 2026042901 3600 1800 604800 60
```

Все ответы имеют форму, неотличимую от стандартного BIND/Knot для свежеподнятой зоны. Active prober не получает сигналов о туннеле.

### Known limitation: NS host A-запрос

```
$ dig @150.241.94.29 ns.t.ivantopgaming.ru A
;; status: NXDOMAIN, AA=1
```

Это противоречие с публичной DNS, где `ns.ivantopgaming.ru → 150.241.94.29` (glue-record оператора). Внимательный prober может это заметить. Принимаем как known limitation; реализация corner-case'a (либо параметризуемый IP оператора, либо проксирование в публичный DNS) — отдельная follow-up задача за рамками G3.

Обоснование: 99% активного probing'a проверяет SOA/NS-структуру зоны и случайные имена; саму NS-host A-запись пробуют редко.

### Truncate path

`rebuildAsTruncated` получает один build-step:
- 1-я попытка: Question + Authority + Additional (OPT). Если влазит — ОК.
- Fallback: drop Authority и Additional, оставить только Question + TC=1.

Сейчас функция Authority не сохраняла. Подкорректируем.

## План коммитов

Атомарные, на ветке `fix/audit-pass-1`:

1. `feat(server/zone): synthesize SOA and NS records` — новый файл `zone.go` + тесты `zone_test.go`. Не используется в main.go пока.
2. `refactor(server): responseFor takes zoneInfo, drops paranoia bool` — пробрасываем тип, сохраняем старое поведение `paranoidResponse` для совместимости в этом коммите.
3. `feat(server): real auth-NS responses for non-tunnel queries` — переписываем `responseFor`, удаляем `paranoidResponse`. Тесты на apex SOA/NS/A/AAAA/MX, NXDOMAIN+SOA, REFUSED.
4. `feat(server): AAAA-blend returns empty Answer + SOA` — закрытие #9.
5. `fix(server): drop -paranoia flag and Paranoia config field` — финал миграции.
6. `fix(server/truncate): preserve Authority in rebuildAsTruncated` — мелкая правка G1-добавленного хелпера.
7. `feat(server/e2e): test prober queries return REFUSED outside zone` — новый E2E.
8. `fix(client): remove -obfuscate flag and sendDecoy` — клиентская часть #8. Включая обновление start-client.sh.
9. `docs: document G3 stealth changes` — README обновления.

При финальном squash-merge в master весь G3 станет одним коммитом.

## Тестирование

### Server unit (`dnstt-server/zone_test.go`)

- `TestNewZoneInfo_Basic`
- `TestNewZoneInfo_Apex_DeepLabels`
- `TestSOARDataWireFormat`

### Server unit (`dnstt-server/main_test.go`, расширение)

- `TestResponseFor_OutsideZone_Refused`
- `TestResponseFor_ApexSOA`
- `TestResponseFor_ApexNS`
- `TestResponseFor_ApexA`
- `TestResponseFor_ApexAAAA`
- `TestResponseFor_ApexMX`
- `TestResponseFor_NonExistentSubdomain_A`
- `TestResponseFor_NonExistentSubdomain_MX`
- `TestResponseFor_TunnelTXT_HappyPath`
- `TestResponseFor_TunnelAAAA_BlendPoll` — закрывает #9, никаких `::`
- `TestResponseFor_BadBase32`
- `TestResponseFor_PayloadTooShort`

### E2E (`e2e_test.go`)

- Существующие (`TestSessionE2E`, `TestSessionE2E_SOCKS5`, `TestSessionE2E_ParamMismatch`) обновить под новые сигнатуры.
- Новый `TestSessionE2E_ProberQueriesIgnored` — параллельно с туннельной сессией шлём `evil.com A`; ожидаем REFUSED + туннель продолжает работать.

### Smoke

Re-run `scripts/smoke-multipath.sh` (G1 Task 10) — должен по-прежнему проходить (multipath работает). Дополнительно:

```bash
dig @150.241.94.29 t.ivantopgaming.ru SOA
# должна показать SOA Answer
dig @150.241.94.29 nonexistent.t.ivantopgaming.ru A
# должна показать NXDOMAIN с SOA в Authority
dig @150.241.94.29 google.com A
# должна показать REFUSED
```

## Принято

Дизайн утверждён пользователем 2026-04-29.
