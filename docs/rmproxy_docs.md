# rmproxy — документация проекта

## 1. Назначение

`rmproxy` — это TLS reverse proxy для Astra Linux SE, который совмещает:

- аутентификацию клиента через Kerberos/SPNEGO (`Authorization: Negotiate`);
- локальное кэширование результата авторизации в JWT-cookie;
- проверку мандатного доступа (MAC) на основе атрибутов пользователя и хостов;
- проксирование разрешённых запросов на backend по TCP.

Проект ориентирован на окружение Astra Linux / FreeIPA / SSSD / LDAP / PARSEC.

---

## 2. Что лежит в репозитории

| Файл | Назначение |
|---|---|
| `.gitignore` | Исключает из репозитория каталог `cert/`, бинарник `proxy` и файл `notes.txt`. |
| `README.md` | Краткая русско-английская инструкция по зависимостям, сборке и первичной настройке. |
| `mrp.conf` | Пример runtime-конфига: порт прослушивания, backend-адрес, LDAP/DC host, путь к сертификатам. |
| `config.h` | Описание структуры конфигурации `pcfg`. |
| `config.c` | Простой парсер `key = value` для `mrp.conf`. |
| `http.h` | Интерфейсы HTTP/JWT-утилит и структура JWT claims. |
| `http.c` | Чтение HTTP-заголовков, разбор `Host` и `Authorization: Negotiate`, Base64, генерация/проверка JWT, ответы `401`, `302`, `403`. |
| `sssd.h` | Заголовок для работы с SSSD и LDAP. |
| `sssd.c` | Получение атрибута пользователя из SSSD InfoPipe и атрибута хоста из LDAP по GSSAPI bind. |
| `proxy.c` | Основной сервер: TLS listener, fork-per-connection, Kerberos-auth, MAC-проверка и проксирование в backend. |
| `74x-ald-host-mac.ldif` | LDAP schema extension: добавляет атрибут `x-ald-host-mac` и objectClass `x-ald-host-parsec`. |

---

## 3. Архитектура

### 3.1. Логические компоненты

Проект можно разделить на 4 слоя:

1. **TLS listener и connection handling**
   - принимает входящие TCP-соединения;
   - поднимает TLS;
   - форкает дочерний процесс на клиента.

2. **HTTP + Kerberos/SPNEGO**
   - считывает HTTP headers;
   - извлекает `Authorization: Negotiate`;
   - завершает GSSAPI-аутентификацию;
   - определяет principal пользователя.

3. **MAC decision engine**
   - получает MAC-атрибут пользователя из SSSD;
   - получает MAC-атрибуты хостов из LDAP;
   - сравнивает уровни через PARSEC API;
   - формирует JWT с флагом доступа.

4. **Backend bridge**
   - устанавливает TCP-соединение с backend;
   - пересылает текущий HTTP-запрос;
   - прозрачно мостит поток данных клиент ↔ backend.

### 3.2. Модель процесса

Сервер работает по схеме **accept + fork**:

- родительский процесс слушает входящий порт;
- на каждое новое подключение создаётся дочерний процесс;
- дочерний процесс выполняет весь TLS/auth/proxy pipeline;
- завершившиеся дочерние процессы подчищаются через `SIGCHLD`.

---

## 4. Поток обработки запроса

Ниже — фактический сценарий работы текущей реализации.

### 4.1. Первый заход клиента

1. Клиент подключается к `rmproxy` по TLS.
2. Прокси считывает HTTP headers.
3. Если в запросе нет валидного `jwt` cookie, прокси ожидает Kerberos/SPNEGO.
4. Если заголовка `Authorization: Negotiate` нет, отправляется:
   - `HTTP/1.1 401 Unauthorized`
   - `WWW-Authenticate: Negotiate`
5. После завершения GSSAPI-аутентификации прокси получает имя клиента (Kerberos principal).
6. Прокси вычисляет флаг `has_access` на основе MAC-меток.
7. Формируется JWT payload:
   ```json
   {
     "uname": "<principal>",
     "has_access": 0|1,
     "exp": <unix_time>
   }
   ```
8. Клиенту возвращается редирект:
   - `HTTP/1.1 302 Found`
   - `Set-Cookie: jwt=...; HttpOnly; Secure; SameSite=Strict; Path=/`
   - `Location: /`

### 4.2. Повторный заход после редиректа

1. Браузер повторяет запрос уже с cookie `jwt=...`.
2. Прокси проверяет подпись JWT.
3. Если cookie проходит проверку, исходный HTTP-запрос сохраняется в буфер `prefetch_req`.
4. JWT декодируется, из него извлекаются `uname`, `has_access`, `exp`.
5. Если `has_access == 1`, прокси открывает соединение с backend и пересылает запрос.
6. Если `has_access != 1`, клиент получает `403 Forbidden`.

---

## 5. Алгоритм принятия решения по MAC

Реализованный алгоритм выглядит так:

1. Из SSSD InfoPipe для пользователя читается атрибут `x-ald-user-mac`.
2. Из LDAP читается `x-ald-host-mac` для:
   - хоста каталога / DC, указанного в `dc_url`;
   - клиентской машины, определённой через reverse lookup.
3. Строки MAC-атрибутов разбираются на две части: условный минимум и максимум.
4. Через API PARSEC создаются `mac_t`-объекты.
5. Сравниваются **минимальные** MAC-уровни пользователя и клиентского хоста.
6. Берётся более «низкий» из двух — это фактический субъектный уровень.
7. Этот уровень сравнивается с MAC-уровнем целевого хоста.
8. При результате `>=` выставляется `has_access = 1`, иначе `0`.

---

## 6. Конфигурация

### 6.1. Формат `mrp.conf`

Поддерживаются следующие параметры:

```ini
port = 8888
t_port = 8000
t_addr = 0.0.0.0
dc_url = astraipa.domain.net
cert_path = ./cert/
```

### 6.2. Значение параметров

| Параметр | Значение |
|---|---|
| `port` | Порт, на котором reverse proxy принимает TLS-клиентов. |
| `t_port` | TCP-порт backend-сервиса. |
| `t_addr` | IPv4-адрес backend-сервиса. В коде используется `inet_pton(AF_INET, ...)`, поэтому ожидается именно IPv4 literal, а не DNS-имя. |
| `dc_url` | Хост LDAP/DC, к которому выполняется LDAP bind и lookup `x-ald-host-mac`. |
| `cert_path` | Каталог, где лежат `cert.pem` и `key.pem`. |

### 6.3. Ограничения текущего парсера

Парсер в `config.c` минималистичен:

- читает только строки вида `name = value`;
- не поддерживает секции;
- не поддерживает комментарии;
- не валидирует полноту обязательных полей;
- использует буфер `128` байт на строку, поэтому слишком длинные строки будут обрезаны.

---

## 7. Сборка

Способ сборки:

```bash
gcc proxy.c sssd.c config.c http.c -o proxy -lpdp -lgssapi_krb5 -lcrypto -lsystemd -lldap -lssl
```

### Зависимости

runtime/build-time зависимости:

- `libsystemd-dev`
- `parsec-dev`
- `libkrb5-dev`
- `libldap-dev`
- `libssl-dev`

По линковке и заголовкам используются:

- GSSAPI / Kerberos;
- OpenSSL;
- OpenLDAP client libraries;
- SSSD InfoPipe через `sd-bus`;
- PARSEC MAC API.

---

## 8. Подготовка окружения

### 8.1. Сертификаты

Предлагается сгенерировать self-signed сертификаты и положить их в `./cert`:

```bash
mkdir -p cert
openssl req -x509 -newkey rsa:4096 \
  -keyout cert/key.pem \
  -out cert/cert.pem \
  -sha256 -days 3650 -nodes \
  -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=localhost"
```

### 8.2. Kerberos / keytab

Нужно обеспечить:

- актуальный Kerberos ticket cache;
- доступность HTTP keytab для пользователя, от имени которого запускается процесс;
- корректную настройку сервисного principal `HTTP/...`.

Запуск:

```bash
sudo execaps -c 0x00004 env KRB5_KTNAME=/var/lib/ipa/gssproxy/http.keytab ./proxy
```

### 8.3. LDAP schema и IPA-атрибуты

Перед использованием нужно добавить схему из `74x-ald-host-mac.ldif`, которая объявляет:

- атрибут `x-ald-host-mac`;
- objectClass `x-ald-host-parsec`.

```bash
ipa host-mod astraipa.domain.net --addattr=objectClass=x-ald-host-parsec
ipa host-mod astraipa.domain.net --addattr=x-ald-host-mac="2:0x2:2:0x2"
ipa permission-add "Read host mac" --type=host --right={read,compare,search} --attrs=x-ald-host-mac --bindtype=all
```

### 8.4. SSSD

Нужно, чтобы в `sssd.conf` были доступны пользовательские атрибуты:

- в domain-секции — `x-ald-user-mac`;
- в `[ifp]` — `user_attributes = +x-ald-user-mac`.

Перезагрузить `dirsrv` и `sssd` после изменения схемы и настроек.

---

## 9. Поведение HTTP-слоя

`http.c` реализует несколько базовых функций протокола.

### 9.1. Поддерживаемые ответы

- `401 Unauthorized` с `WWW-Authenticate: Negotiate`
- `302 Found` с установкой `jwt` cookie
- `403 Forbidden` при отказе в доступе

### 9.2. Что именно умеет модуль

- дочитывать HTTP headers до `\r\n\r\n`;
- извлекать `Host:`;
- извлекать `Authorization: Negotiate ...`;
- кодировать и декодировать Base64;
- формировать JWT с HMAC-SHA256;
- проверять подпись JWT;
- декодировать payload и извлекать claims.

### 9.3. Структура JWT claims

```c
typedef struct {
    char uname[256];
    int has_access;
    long exp;
} s_jwt;
```

Cookie выставляется с атрибутами:

- `HttpOnly`
- `Secure`
- `SameSite=Strict`
- `Path=/`

---

## 10. Поведение backend bridge

После решения `has_access == 1` прокси:

1. создаёт TCP-сокет;
2. подключается к `t_addr:t_port`;
3. передаёт сохранённый prefetch-запрос;
4. далее работает в режиме прозрачного мостирования:
   - TLS client → backend socket
   - backend socket → TLS client

### Ограничения

- upstream-соединение к backend выполняется **без TLS**;
- backend должен быть доступен по IPv4 адресу;
- код не делает HTTP-aware rewriting заголовков;
- это низкоуровневый stream bridge, а не полнофункциональный L7 reverse proxy.

---

## 11. Известные ограничения и риски реализации

Этот раздел важен для сопровождения проекта. Ниже — то, что видно непосредственно по текущему коду.

### 11.1. Жёстко зашитый JWT secret

В `http.c` используется:

```c
#define JWT_SECRET "rmproxysecret"
```

Это означает, что секрет подписи не настраивается через конфиг и одинаков для всех инсталляций, если код не пересобран.

### 11.2. Проверка срока жизни JWT реализована, но результат не используется в `proxy.c`

`decode_jwt(...)` умеет вернуть `-1`, если токен просрочен. Но в `main()` значение, записанное в переменную `n`, не влияет на решение о допуске — далее проверяется только `jwt_claim.has_access`.

Практический эффект: просроченный токен может быть принят, если в нём стоит `has_access = 1` и подпись валидна.

### 11.3. Access decision привязан к `dc_url`

Хотя в процессе аутентификации из `Host:` извлекается FQDN запроса, в `payload_gen(...)` фактически используется `cfg.dc_url`. Переданный параметр `target_fqdn` не участвует в вычислении доступа.

Практический эффект: решение о допуске сейчас выглядит привязанным к MAC-метке хоста каталога / IPA, а не к целевому HTTP-host/backend.

### 11.4. `*_max` части MAC-меток не используются

Код разбирает строку MAC на минимум и максимум, но в PARSEC-сравнении участвуют только `mac_str_user_min`, `mac_str_host_min`, `mac_str_userhost_min`.

### 11.5. LDAP base DN захардкожен

В `sssd.c` используется:

```c
const char *base_dn = "cn=computers,cn=accounts,dc=domain,dc=net";
```

Это привязывает код к конкретной LDAP-структуре и требует модификации исходников для другого домена.

### 11.6. Конфиг-парсер очень хрупкий

- нет обработки комментариев;
- нет защиты от отсутствующих ключей;
- нет валидации диапазонов портов;
- длина строки ограничена 128 байтами.

### 11.7. Только IPv4 для backend

Поскольку используется `inet_pton(AF_INET, cfg.t_addr, ...)`, backend-адрес должен быть IPv4 literal.

### 11.8. Масштабирование ограничено

Fork-per-connection упрощает код, но делает проект менее удобным для высокой нагрузки по сравнению с event-driven архитектурой.

---

## 12. Практический сценарий запуска

Ниже — минимальный рабочий порядок действий.

1. Подготовить FreeIPA/LDAP schema и права чтения `x-ald-host-mac`.
2. Настроить SSSD InfoPipe и публикацию `x-ald-user-mac`.
3. Получить рабочий HTTP keytab для сервисного principal.
4. Сгенерировать TLS-сертификаты в `./cert/`.
5. Заполнить `mrp.conf`:
   - `port` — внешний TLS-порт;
   - `t_addr` / `t_port` — реальный backend;
   - `dc_url` — LDAP/DC host;
   - `cert_path` — путь к сертификатам.
6. Собрать бинарник.
7. Запустить процесс с нужными правами и переменной `KRB5_KTNAME`.
8. Проверить, что:
   - Kerberos negotiation проходит;
   - cookie `jwt` выставляется;
   - при `has_access=1` запрос уходит в backend;
   - при `has_access=0` возвращается `403`.

---

## 13. Развитию проекта

Если проект планируется использовать не как прототип, а как поддерживаемый сервис, логично вынести в ближайший backlog следующие задачи:

1. **Сделать secret JWT конфигурируемым**
   - через `mrp.conf` или переменную окружения;
   - исключить hardcode в исходниках.

2. **Исправить обработку `decode_jwt(...)`**
   - учитывать код возврата;
   - отклонять просроченные токены.

3. **Использовать реальный target host**
   - либо `Host:` из HTTP-запроса;
   - либо отдельный параметр backend FQDN;
   - не подменять его `dc_url`.

4. **Убрать hardcode `base_dn`**
   - сделать его параметром конфига.

5. **Расширить конфиг**
   - поддержка комментариев;
   - проверка обязательных полей;
   - валидация портов и путей.

6. **Нормализовать модель MAC-решения**
   - документировать формат атрибута;
   - решить, должны ли использоваться и `min`, и `max` компоненты.

7. **Добавить нормальные логи**
   - syslog/journald;
   - уровни логирования;
   - явные сообщения об отказе в доступе.

8. **Добавить unit/service packaging**
   - systemd unit;
   - пример запуска в production.

