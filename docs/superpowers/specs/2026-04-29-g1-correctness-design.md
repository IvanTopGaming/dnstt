# G1 — корректность транспортного слоя (дизайн)

**Дата:** 2026-04-29
**Ветка:** `fix/audit-pass-1`
**Статус:** утверждено пользователем
**Покрывает:** дефекты #1, #4, #14, #15, #16, #17 из аудита 2026-04-29

## Контекст

Аудит выявил, что multipath-режим клиента архитектурно не работает: каждый транспорт обёрнут в собственный `DNSPacketConn`, который генерирует свой `ClientID`. KCP-сеанс при round-robin оказывается размазан по двум разным KCP-сессиям на сервере, поток не ассемблируется. Сопутствующие баги (`MultiPacketConn.SetDeadline` no-op, `int`-overflow в индексе round-robin, race на `firstUsed`, неконтролируемый truncate UDP-ответа, отсутствие согласования FEC/compress между клиентом и сервером) усугубляют картину.

Совместимость не держим: проект мейнтейнится в одних руках, форк используется только владельцем.

## Цели

1. Multipath даёт реально работающий tunnel поверх нескольких DNS-транспортов с одним KCP-сеансом и одним `ClientID`.
2. KCP-уровневые тайм-ауты работают корректно во всех режимах (single, auto, multipath).
3. UDP-ответ сервера всегда валидный wire format, даже при оверсайзе.
4. Клиент и сервер обнаруживают и сообщают о несовпадении параметров FEC/compress на handshake'е, не давая трафику молча идти в никуда.
5. Никаких race conditions в фабрике PacketConn.

## Не цели

- Sticky-multipath (балансировка по smux-стримам). Отдельный refactor.
- DoQ в multipath. У него своё framing (RFC 9250), не вписывается в DNS-уровневый round-robin без значительной переработки.
- Backwards compatibility со старым клиентом/сервером.

## Архитектура

### Слои клиента

```
TCP-listener (local)
  │
smux session
  │
Noise channel
  │
KCP conn       ← один conv-id, один ClientID
  │
DNSPacketConn  ← инкапсулирует ClientID + DNS-кодирование/декодирование
  │ WriteTo/ReadFrom несут уже-готовые DNS wire-сообщения
  │
┌─┴─┐
│   ├── single/auto: HTTPPacketConn / TLSPacketConn / fixedAddrConn(UDP)
│   │   (DoQ остаётся отдельной веткой — он сам по себе DNS-уровневый)
│   │
│   └── multipath: MultiPacketConn ─► [HTTPPacketConn, TLSPacketConn, fixedAddrConn(UDP)]
└───
```

**Ключевая инверсия:** `MultiPacketConn` оборачивает голые транспорты, а не `DNSPacketConn`. Уровень wire-сообщений у multi и у транспортов совпадает — DNS wire format. `DNSPacketConn` ровно один поверх всего, что гарантирует единый `ClientID` и единое место кодирования.

### DoQ — отдельная ветка

`QUICPacketConn` имеет собственный length-prefixed framing и не работает на «DNS-over-UDP-датаграмм»-уровне. В single и auto-режимах DoQ передаётся в `makeConn` напрямую, без обёртки `DNSPacketConn` (как и сейчас). В multipath DoQ не участвует.

### Сервер — без архитектурных изменений

На сервере один `ClientID` → одна KCP-сессия — это уже корректно. Меняется только handshake (см. §«Согласование параметров») и truncate-fallback (см. §«Корректный truncate»).

## Компоненты

### `dnstt-client/main.go`

**`makeDoH/makeDoT/makeUDP`** меняют сигнатуру:
- Было: `func() (net.PacketConn, net.Addr, error)` возвращал уже-обёрнутый `DNSPacketConn`.
- Стало: возвращает голый транспорт без DNS-обёртки.
- Обёртка в `DNSPacketConn` происходит на callsite — после выбора single/auto-транспорта или после построения `MultiPacketConn`.

**`makeDoQ`** не меняется (см. выше).

**Multipath-блок:**
- Удаляется хрупкая `sync.Once`-обёртка вокруг closure'а с `result` (текущий `firstUsed`-эквивалент в multipath написан так, что `result` захватывается некорректно). Заменяется простым последовательным `firstUsed bool`, который безопасен потому что `makeConn` вызывается строго sequential из `run()`.
- Все три транспорта (DoH/DoT/UDP) собираются в `MultiPacketConn`, который оборачивается **одним** `NewDNSPacketConn`. KCP открывается на этом `DNSPacketConn`.
- `kcpCfg.window` поднимается до 512 при multipath, как и сейчас (для unequal latency).

**Single-режим:**
- `chosen()` вызывается один раз для connectivity check, результат сохраняется и отдаётся первым же вызовом `makeConn` (через простой `firstUsed bool` без race-prone state-tricks).
- На реконнекте — `chosen()` снова, без хранения первого conn'а.

### `dnstt-client/multi.go`

**Изменения:**
1. `idx` → `atomic.Uint64`, индекс `int(idx.Add(1) % uint64(len(conns)))`.
2. `SetDeadline/SetReadDeadline/SetWriteDeadline` пробрасываются на все underlying conn'ы:
   ```go
   func (c *MultiPacketConn) SetDeadline(t time.Time) error {
       var first error
       for _, conn := range c.conns {
           if err := conn.SetDeadline(t); err != nil && first == nil {
               first = err
           }
       }
       return first
   }
   ```
3. `Close` идемпотентен через `sync.Once`.
4. Счётчик активных reader-горутин: когда последняя выходит — закрывается `recvCh`, `ReadFrom` возвращает `io.EOF`, KCP-сеанс корректно завершается вместо зависания.

### `dnstt-client/auto.go`

`transportMaker` остаётся `func() (net.PacketConn, net.Addr, error)`, но теперь возвращает голый транспорт. Оборачивание в `DNSPacketConn` — на стороне `main.go` после `tryTransports`.

### `dnstt-client/dns.go`

Без функциональных изменений. Возможно — обновление doc-комментариев, подчёркивающих, что в multipath единственный экземпляр оборачивает `MultiPacketConn`.

### `noise/noise.go`

`NewClient` принимает опциональный `[]byte` payload, передаваемый в `-> e, es`. `NewServer` возвращает прочитанный payload вызывающему через дополнительный return value или callback. Вариант реализации: расширить сигнатуру до `NewClientWithPayload` / `NewServerWithPayload`, оставив текущие функции как обёртки с пустым payload (для тестов и совместимости внутри проекта).

### `dnstt-server/main.go`

1. **Truncate fix** (см. §«Корректный truncate»).
2. **Чтение handshake payload** — после `noise.NewServer` сервер получает 4 байта параметров клиента и сравнивает с локальной конфигурацией. Mismatch → лог warning + закрытие.
3. **Auth и rate-limit-related вещи** в этой группе не трогаем — они уезжают в G2/последующие группы.

## Поток данных

### Отправка (клиент → сервер)

```
TCP local conn
  │ io.Copy
smux.Stream.Write
  │ frame'ы в smux
Noise.Write          ← AEAD-шифрование, 16-bit length prefix
  │
KCP.WriteTo          ← KCP-фрейм с conv-id; MTU-нарезка
  │
DNSPacketConn.WriteTo ← OutgoingQueue для addr=DummyAddr{}
  │
DNSPacketConn.sendLoop:
  │   - кодирует ClientID + padding + payload в base32-имя
  │   - формирует DNS query (TXT или AAAA для poll)
  │   - WireFormat
  │   - WriteTo на нижележащий transport
  ▼
[single/auto] HTTPPacketConn.WriteTo / TLSPacketConn.WriteTo / fixedAddrConn.WriteTo / QUICPacketConn.WriteTo
[multi]       MultiPacketConn.WriteTo:
                 i = int(idx.Add(1) % uint64(len(conns)))
                 conns[i].WriteTo(...)
```

### Приём (сервер → клиент)

```
[transport].ReadFrom: DNS wire bytes
  │
[multi] readFrom-горутина (одна на conn) пихает в общий recvCh
        MultiPacketConn.ReadFrom отдаёт следующее сообщение
  │
DNSPacketConn.recvLoop:
  │   - dns.MessageFromWireFormat
  │   - dnsResponsePayload(): извлекает payload из TXT-ответов (AAAA — пустой poll)
  │   - бьёт payload на length-prefixed packet'ы
  │   - QueueIncoming для KCP
  │
KCP.ReadFrom → Noise → smux → local TCP
```

## Согласование параметров (handshake payload)

**Wire format первого Noise-сообщения клиента (`-> e, es`):**

| offset | size | поле | описание |
|---|---|---|---|
| 0 | 1 | `fec_data` | uint8, должно совпадать с серверным |
| 1 | 1 | `fec_parity` | uint8, должно совпадать с серверным |
| 2 | 1 | `flags` | bit 0: compress |
| 3 | 1 | `reserved` | =0 |

Итого 4 байта.

**Сервер:**
- Если `len(payload) != 4` → `errors.New("client did not advertise parameters")`.
- При несовпадении логирует:
  ```
  client param mismatch: client fec-data=4 fec-parity=2 compress=true; server fec-data=0 fec-parity=0 compress=false
  ```
  и закрывает соединение.
- При совпадении — обычная `<- e, es` без payload.

**Клиент:**
- Всегда шлёт 4 байта.
- Если сервер закрыл соединение на handshake — выводит ошибку «check that fec/compress params match server» и прерывается без backoff.

## Корректный truncate

Текущее поведение (`dnstt-server/main.go:843-847`): `buf = buf[:maxUDPPayload]; buf[2] |= 0x02 // TC=1` — режет посреди RR, оставляя невалидный wire format.

**Новое поведение:**
- При `len(buf) > maxUDPPayload` пересобираем `rec.Resp`:
  - Сохраняем `Question` и (если был) OPT-RR в `Additional`.
  - Очищаем `Answer` и `Authority`.
  - Ставим TC=1, оставляем AA=1 если был.
  - Заново сериализуем.
- Если даже это превышает лимит (теоретически: длинное Question-имя плюс OPT) — fallback на `Question`-only без OPT, всё ещё валидный wire format.
- Инкрементируем `expvar`-counter `metricTruncated`. Лог-сообщение печатаем только если со времени последнего прошло ≥1 сек (атомарный `lastLog` Unix-nano), чтобы не флудить при вспышке оверсайза.

Резолвер по TC=1 должен повторить через TCP. Сервер TCP не слушает — клиент увидит таймаут и KCP retransmit'ит. Это лучше, чем broken wire format.

## Обработка ошибок

**`MultiPacketConn`:**
- WriteTo: ошибка от `conns[i]` пробрасывается; KCP retransmit'ит.
- ReadFrom-горутины: при ошибке — выход; счётчик активных reader'ов; когда 0 — `recvCh` закрывается.
- `SetDeadline`: первая ошибка возвращается, но все conn'ы пробуются.
- `Close`: идемпотентен.

**Handshake mismatch:**
- Сервер закрывает Noise-канал. Клиент видит `io.EOF` на следующем `Read`. Приложение выводит конкретное сообщение.

## Тестирование

### Unit-тесты

**`dnstt-client/multi_test.go`** (новый):
- `TestMultiPacketConn_WriteRoundRobin`
- `TestMultiPacketConn_ReadMerge`
- `TestMultiPacketConn_IndexNoOverflow` — стартуем `idx` близко к `^uint64(0)`, делаем тысячи WriteTo, не паникуем.
- `TestMultiPacketConn_SetDeadline` — проверка проброса
- `TestMultiPacketConn_AllReadersDie_Read_Returns` — ReadFrom не зависает.

**`dnstt-server/main_test.go`** (расширение):
- `TestSendLoop_OversizedTruncatedCleanly` — оверсайз TXT-payload, проверка валидности wire format и TC=1.

**`noise/noise_test.go`** (расширение):
- `TestHandshake_PayloadRoundTrip`
- `TestHandshake_RejectEmptyParams`

### Integration (in-memory) — `dnstt-server/e2e_test.go`

- `TestSessionE2E_ParamMatch` — клиент и сервер с одинаковыми FEC/compress.
- `TestSessionE2E_ParamMismatch` — отказ на handshake.

### Smoke на сервере `150.241.94.29`

Скрипт `scripts/smoke-test.sh`:
1. Деплой свежего `dnstt-server` через scp + systemd.
2. Сервер запущен в режиме `-socks5` (клиент сам выбирает destination). Локально: `dnstt-client -multipath -doh https://1.1.1.1/dns-query -dot 1.1.1.1:853 -udp 1.1.1.1:53 -pubkey-file server.pub t.ivantopgaming.ru 127.0.0.1:7000`.
3. `curl --proxy socks5h://127.0.0.1:7000/ https://ifconfig.me/` → IP сервера.
4. Метрики (`-debug-addr`): один активный `metricSessions`, не два.
5. Trip-test: `tc qdisc add dev eth0 root netem delay 200ms` на UDP-пути, throughput не должен падать в 0.

Smoke на сервере — раз на группу, не на каждый коммит.

## План коммитов внутри ветки `fix/audit-pass-1`

Все коммиты атомарные, по одному на дефект:

1. `fix(client): single ClientID across multipath transports`
2. `fix(client/multi): propagate SetDeadline to underlying conns`
3. `fix(client/multi): use atomic.Uint64 for round-robin index`
4. `refactor(client): simplify makeConn first-call handling`
5. `feat(handshake): negotiate FEC/compress params via Noise payload`
6. `fix(server): preserve wire format on UDP truncation`

При merge в master — squash в один коммит с резюмирующим сообщением.

## Открытые вопросы

Нет.

## Принято

Дизайн утверждён пользователем 2026-04-29.
