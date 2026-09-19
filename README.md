# my-socks-server

SOCKS5-прокси на Rust/Tokio для доступа через удалённый дата-центр. Замена `ssh -D`, который со временем
падает с `too many open files`. Сервер рассчитан на порт, открытый в интернет, и на долгую работу без
утечек дескрипторов.

- SOCKS5 (RFC 1928), только `CONNECT`; адреса IPv4, IPv6 и DOMAIN (имя резолвится на сервере).
- Аутентификация username/password (RFC 1929), несколько пользователей. Метод «без аутентификации» не
  принимается. Пароли сравниваются за постоянное время.
- Защита от SSRF: приватные и служебные адреса запрещены. Решение принимается по IP, к которому
  реально идёт подключение (после DNS), поэтому DNS rebinding не помогает. Внутренние ресурсы
  открываются явно: `allow_internal` и `internal_whitelist`.
- Whitelist клиентских IP/CIDR, бан IP после серии неудачных входов, запрет портов (по умолчанию 25).
- Каждая фаза соединения ограничена таймаутом, лимит одновременных соединений, TCP keepalive,
  graceful shutdown.

## Настройки: `~/.mysocksserver`

Настройки читаются из YAML-файла `~/.mysocksserver` (как `~/.mynosqlserver` у my-no-sql-server).
Ключи в snake_case. Обязателен только `users`. Неизвестный ключ считается ошибкой: опечатка не
отключит защиту молча. Полный пример с комментариями лежит в [settings.example.yaml](settings.example.yaml).

```yaml
listen_address: 0.0.0.0:1080
users:
  - username: alice
    password: "long-random-password"
client_whitelist: [203.0.113.10, 198.51.100.0/24]
allow_internal: false
internal_whitelist:
  - 10.20.0.5:5432
  - 10.30.0.0/24
```

| ключ | по умолчанию | смысл |
|---|---|---|
| `listen_address` | `0.0.0.0:1080` | адрес и порт (`[::]:1080` для dual-stack) |
| `users` | — | пары `username`/`password`, 1–255 байт каждая |
| `max_connections` | `4096` | одновременных клиентских соединений; сверх лимита соединение сразу закрывается |
| `handshake_timeout_sec` | `10` | greeting + аутентификация + запрос |
| `connect_timeout_sec` | `15` | DNS + TCP connect к цели |
| `idle_timeout_sec` | `300` | нет трафика ни в одну сторону |
| `shutdown_grace_sec` | `10` | сколько активные соединения живут после SIGTERM/SIGINT |
| `stats_interval_sec` | `60` | период строки `stats` в логе |
| `client_whitelist` | пусто = все | IP/CIDR клиентов; остальные закрываются сразу после `accept()` |
| `blocked_ports` | `[25]` | запрещённые порты назначения, действуют и на whitelist |
| `allow_internal` | `false` | открыть все приватные сети |
| `internal_whitelist` | пусто | точечно открытые внутренние адреса (см. ниже) |
| `ban_max_failures` | `5` | неудачных входов за окно до бана; `0` выключает баны |
| `ban_window_sec` | `600` | окно подсчёта неудач |
| `ban_duration_sec` | `3600` | длительность бана |

При ошибке в настройках сервер не стартует (код выхода 1) и называет файл или ключ:

```text
ERROR invalid setting `internal_whitelist`: 'db:5432': expected an IP address or CIDR
ERROR cannot read settings file /home/socks/.mysocksserver: No such file or directory (os error 2)
```

Логи настраиваются переменными окружения: `RUST_LOG` задаёт уровень (по умолчанию `info`),
`LOG_FORMAT=json` включает JSON (по умолчанию текст).

### Внутренние ресурсы

| адреса назначения | когда разрешены |
|---|---|
| публичные | всегда (кроме `blocked_ports`) |
| приватные: `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7` | `allow_internal: true` или запись в `internal_whitelist` |
| loopback `127/8`, `::1`, link-local `169.254/16`, `fe80::/10` | только запись в `internal_whitelist` |
| `0.0.0.0/8`, multicast, `240/4`, broadcast, `::`, `::a.b.c.d` | никогда |

- `allow_internal: true` открывает сразу все приватные сети.
- `internal_whitelist` открывает ровно перечисленное: IP или CIDR, при необходимости с портом или
  диапазоном портов: `10.20.0.5:5432`, `10.30.0.0/24:8000-8100`, `fd00::1`, `"[fd00::/64]:443"` (IPv6 с
  портом в скобках, в YAML в кавычках).
- Loopback (сервисы самого хоста прокси) и link-local (в облаках там metadata-сервис
  `169.254.169.254` с учётными данными) флагом не открываются: только явной записью.
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`) проверяется как IPv4. Адреса NAT64/6to4 проверяются по
  вложенному IPv4.
- Для DOMAIN проверяется каждый адрес из DNS; подключение идёт только к разрешённым.

## Запуск

### Локально

```bash
cp settings.example.yaml ~/.mysocksserver && chmod 600 ~/.mysocksserver   # отредактировать
cargo run --release
```

### Docker / docker-compose

Образ многоступенчатый: статический бинарь `x86_64-unknown-linux-musl` в пустом образе `scratch`,
запуск от `nobody` (65534). Сервер ищет настройки в `$HOME/.mysocksserver`, в образе
`HOME=/home/socks`.

```bash
cp settings.example.yaml .mysocksserver            # отредактировать
sudo chown 65534 .mysocksserver && chmod 600 .mysocksserver
docker compose up -d --build
```

В [docker-compose.yml](docker-compose.yml) заданы `ulimits nofile 1048576`, `restart: unless-stopped`,
read-only FS, `cap_drop: ALL` и `network_mode: host`. Host-сеть выбрана специально: сервер видит
реальные IP клиентов, а от них зависят `client_whitelist` и баны. Порт берётся из `listen_address`.
Образ собирается под x86_64; на ARM-маке используйте `docker build --platform linux/amd64 .`.

### systemd

Unit: [deploy/my-socks-server.service](deploy/my-socks-server.service) (`DynamicUser=yes`,
`LimitNOFILE=1048576`, `Restart=always`, hardening). Установка описана в комментарии в начале файла.
Настройки лежат в `/etc/my-socks-server/mysocksserver.yaml` с правами root 0600. systemd передаёт их
сервису через `LoadCredential`, а `HOME` указывает на каталог credentials, поэтому сервер находит файл
как `~/.mysocksserver`.

## Проверка

```bash
curl --socks5-hostname alice:password@proxy.example.com:1080 https://ifconfig.me
```

Должен вернуться IP дата-центра. `--socks5-hostname` резолвит имена на стороне прокси: так доступны и
внутренние DNS-имена ДЦ. Если в пароле есть `@ : / %`, закодируйте их в URL или передайте через
`--proxy-user 'alice:pa:ss'`.

## ⚠️ SOCKS5 передаёт пароль открытым текстом

Логин и пароль RFC 1929 идут по сети без шифрования, как и весь проксируемый трафик, если он сам не
зашифрован (HTTPS). Поэтому:

- задайте `client_whitelist`: соединения с других адресов закрываются сразу после `accept()`,
  до чтения первого байта. Без whitelist сервер пишет предупреждение при старте;
- используйте длинные случайные пароли. Бан после `ban_max_failures` неудач защищает от перебора, но не
  от перехвата;
- если клиенты ходят с меняющихся адресов, поставьте прокси за WireGuard/VPN или SSH-туннель
  и слушайте только внутренний адрес.

## Логи

На каждое соединение пишется одна строка `connection closed`:

```json
{"message":"connection closed","conn_id":1,"client":"203.0.113.10:51234","user":"alice",
 "target":"example.com:443","target_addr":"93.184.216.34:443","bytes_in":585,"bytes_out":4824,
 "duration_ms":275,"reason":"completed"}
```

- `bytes_in`: клиент → цель, `bytes_out`: цель → клиент.
- Причины закрытия (`reason`): `completed`, `idle_timeout`, `client_error`, `target_error`,
  `handshake_timeout`, `handshake_io_error`, `protocol_error`, `no_acceptable_auth_method`,
  `auth_failed`, `command_not_supported`, `address_type_not_supported`, `invalid_domain`,
  `denied_by_policy`, `resolve_failed`, `resolved_to_nothing`, `connect_failed`, `connect_timeout`,
  `shutdown`. Подробности, если есть, лежат в поле `detail`.
- Неудачный вход пишется отдельной строкой `authentication failed` с username (пароль не логируется
  никогда), бан — строкой `client banned ...`.
- Соединения, отброшенные сразу после `accept()` (whitelist, бан, лимит), пишутся на уровне `debug` и
  учитываются в счётчиках. При исчерпании лимита есть предупреждение, не чаще раза в 10 с.

Каждые `stats_interval_sec` пишется строка `stats`: `active_connections`, `free_permits`,
`open_fds` (число записей в `/proc/self/fd`), счётчики `accepted`, `rejected_*`, `auth_failures`,
`denied_by_policy`, `bytes_in`/`bytes_out` закрытых соединений, `banned_clients`, `tracked_clients`.

## Почему не течёт

- При старте soft `RLIMIT_NOFILE` поднимается до hard, итог пишется в лог. Если лимит меньше
  `2 × max_connections`, выводится предупреждение.
- Слот семафора занимается сразу после `accept()`. Если слотов нет, соединение тут же закрывается.
- Ошибка `accept()` (включая `EMFILE`/`ENFILE`) логируется, затем пауза 100 мс и следующая попытка.
  Цикл accept не завершается.
- У каждой фазы свой таймаут: handshake 10 с, DNS + connect 15 с. Relay реализован вручную вместо
  `copy_bidirectional`: каждое `read` и `write` обёрнуто в `timeout`, а idle-срок у двух направлений
  общий. Поэтому долгая загрузка при молчащем upload не рвётся, а мёртвое или зависшее соединение
  закрывается. EOF одной стороны превращается в `shutdown()` записи на другой. Ошибка или таймаут
  закрывают обе стороны.
- TCP keepalive (60 с / 10 с × 3) и `TCP_NODELAY` на обоих сокетах. На Linux дополнительно
  `TCP_USER_TIMEOUT` 90 с: он ловит пропавшего пира и во время передачи данных.
- SIGTERM/SIGINT: listener закрывается, активным соединениям даётся `shutdown_grace_sec`, остальные
  закрываются с `reason: shutdown`, затем процесс выходит.

## Тесты

```bash
cargo test                                  # unit + интеграционные + fd-leak
cargo clippy --all-targets -- -D warnings   # в крейте также включён clippy::pedantic
cargo fmt --check
cargo run --release --example fd_stress -- --connections 2000 --timeout-ms 1500
```

- Интеграционные тесты ([tests/integration.rs](tests/integration.rs)) поднимают сервер и echo-сервер и
  проверяют: handshake + auth + CONNECT и передачу данных, DOMAIN, неверный пароль, отказ от «no auth»,
  idle- и handshake-таймауты, политику внутренних адресов, `blocked_ports`, BIND, бан, client whitelist,
  лимит соединений, graceful shutdown и мусор на входе.
- [tests/fd_leak.rs](tests/fd_leak.rs) и пример [examples/fd_stress.rs](examples/fd_stress.rs)
  открывают много соединений и бросают их, не закрывая: половину после handshake, половину на середине
  greeting. После таймаутов число открытых fd возвращается ровно к исходному. Пример выводит отчёт и
  завершается с ненулевым кодом, если что-то утекло.

## Ограничения

- Только `CONNECT`: UDP ASSOCIATE, BIND, SOCKS4 и GSSAPI не поддерживаются.
- DNS идёт через `tokio::net::lookup_host`, то есть через `getaddrinfo` в blocking-потоке. Клиент
  получит ответ по `connect_timeout_sec`, но сам поток живёт, пока системный резолвер не сдастся.
  В musl-образе используется резолвер musl.
- Пароли хранятся в файле настроек открытым текстом (хэшей нет). Изменение настроек требует рестарта.
- Баны хранятся в памяти и сбрасываются при рестарте. Таблица ограничена 100 000 адресами: при
  переполнении новые адреса не учитываются до очистки. IPv6 банится по `/64`.
- Нет лимита соединений на один IP. Клиент из whitelist может занять все слоты; соединение в фазе
  handshake держит слот до `handshake_timeout_sec`. Главная защита здесь `client_whitelist`.
- `bytes_in`/`bytes_out` в строке `stats` учитывают только закрытые соединения.
