# AuthLayer — реализация v0.1

Документ описывает **фактический код** в `authlayer/src` по состоянию на 2026-11-23.
Он не описывает целевую архитектуру из `../../docs/ARCHITECTURE.md`, если соответствующих
функций нет в коде.

> **Статус.** По `../../PROJECT_STATE.md`: `cargo check`/`build`/`fmt` проходят,
> `cargo test` — 0 тестов. Live HTTP smoke: 26/26 с `ADMIN_TOKEN`; без него — 21 passed,
> 5 skipped. Docker image собран: бинарник 13.7 MB, read-only container healthy; локальный
> Mailpit SMTP E2E прошёл, внешний провайдер не тестировался. Browser E2E: 18/18 с Chrome
> CDP virtual authenticator (visible step-up, SameSite=Strict, `al_ceremony`); real-device/
> browser matrix не проверялась. Unrestricted public v0.1 — **NO-GO**; conditional GO —
> только по условиям round-3 review ([`../SECURITY_REVIEW_ROUND3.md`](../SECURITY_REVIEW_ROUND3.md));
> `SECURITY_REVIEW.md` и round 2 — исторические. Внутренние review не заменяют внешний аудит.

## 1. Обзор архитектуры

```text
Браузер
  │  HTTP/JSON + cookie al_session
  ▼
Axum router (src/routes.rs)
  ├─ GET  /, /app.js, /style.css      static/ встроен через include_str!
  ├─ POST /api/auth/*                 OTP + WebAuthn + step-up
  ├─ GET  /api/me
  ├─ GET  /api/sessions
  ├─ POST /api/sessions/revoke-all
  ├─ POST /api/sessions/{id}/revoke
  ├─ GET  /api/passkeys
  ├─ POST /api/passkeys/add/start
  ├─ POST /api/passkeys/add/finish
  ├─ POST /api/passkeys/{id}/revoke
  ├─ POST /api/recovery/regenerate
  ├─ POST /api/auth/recover/*
  ├─ GET  /dev/outbox, /api/dev/outbox   только DEV_MODE
  ├─ GET/POST /admin/login, POST /admin/logout
  ├─ GET  /admin                         admin cookie
  └─ GET  /healthz                       проверяет БД
        │
        ├─ src/auth.rs    OTP, сессии, recovery, advisory failed-attempts, rate limit, IP/UA
        ├─ src/email.rs   EmailSender: outbox или SMTP через lettre
        ├─ src/state.rs   AppState, in-memory challenges, cleanup, rate limiter
        ├─ src/db.rs      SqlitePool (WAL), миграции, audit, cleanup rows/outbox
        └─ src/error.rs   AppError → JSON
        │
        ▼
SQLite (файл authlayer.db)
```

Клиентский UI — vanilla JS в `static/app.js`, без сборщика и framework. Он делает
same-origin `fetch` к API, конвертирует WebAuthn `ArrayBuffer` в base64url и вызывает
`navigator.credentials.create/get`. Сессия живёт в HttpOnly cookie; токены, OTP и
recovery-коды не сохраняются в `localStorage`/`sessionStorage`.

### 1.1. Старт приложения (`src/main.rs`)

1. Инициализируется `tracing_subscriber`; фильтр по умолчанию —
   `authlayer=info,tower_http=info`, переопределяется через `RUST_LOG`.
2. `Config::from_env()` читает env и валидирует: `DEV_MODE` (loopback или
   `ALLOW_INSECURE_DEV_MODE`), `OTP_SECRET` (обязателен вне dev, минимум 32 символа,
   placeholder'ы запрещены), `ADMIN_TOKEN` (минимум 32, placeholder'ы запрещены),
   `EMAIL_PROVIDER` (outbox вне dev требует `ALLOW_OUTBOX_WITHOUT_DEV`), SMTP-поля,
   `SMTP_TLS` (`required` в production; `opportunistic`/`none` только dev), положительные
   TTL, `TRUST_PROXY`/`TRUSTED_PROXY_CIDRS`, `RP_ID` (вне dev равен host `APP_URL`, иначе
   только `ALLOW_RP_ID_PARENT=true`) и cookie production-инварианты (`https` APP_URL,
   `COOKIE_SECURE=true`, `__Host-` имя).
3. В dev-режиме без `OTP_SECRET` создаётся случайный секрет и пишется warning; вне dev
   отсутствие/пустое значение — ошибка старта.
4. `EmailSender::from_config()` валидирует `SMTP_FROM` как mailbox и строит SMTP-транспорт
   `lettre`. В лог пишется только имя провайдера (`outbox`/`smtp`); пароль не логируется.
5. `db::init()` создаёт `SqlitePool` (максимум 5 соединений) с WAL, foreign keys и
   busy timeout 5s, применяет миграции `sqlx::migrate!("./migrations")`, чистит outbox
   старше 1 дня и `cleanup_expired_rows()` для OTP/sessions/recovery/admin_sessions.
   `DATABASE_URL` в логах редактируется (`config.redacted_db_url()`).
6. `WebauthnBuilder::new(&config.rp_id, &config.app_url)` строит WebAuthn-конфигурацию;
   `APP_URL` — origin, `RP_ID` — relying party ID. Ошибка конфигурации останавливает старт.
7. Создаётся `AppState` (пул, конфиг, WebAuthn, `EmailSender`, in-memory maps, rate limiter).
8. Запускается фоновая задача раз в 300 секунд: `AppState::cleanup_expired()` (challenge
   maps, rate limiter), `db::cleanup_outbox()` и `db::cleanup_expired_rows()`.
9. Router оборачивается middleware `Cache-Control: no-store`, затем
   `TraceLayer::new_for_http()`. Сервер запускается с
   `into_make_service_with_connect_info::<SocketAddr>()`; IP берётся из peer, а
   `X-Forwarded-For`/`X-Real-IP` — только если peer входит в `TRUSTED_PROXY_CIDRS`.
10. Graceful shutdown не реализован: процесс завершается по сигналу, незавершённые
    церемонии теряются.

### 1.2. Модули

| Файл | Ответственность |
|---|---|
| `main.rs` | Bootstrap, tracing, Cache-Control no-store, WebAuthn, cleanup task, HTTP listener. |
| `config.rs` | Разбор env (SMTP, TTL, proxy, dev/security flags), значения по умолчанию, `Arc<Config>`. |
| `db.rs` | `SqlitePool` с WAL, миграции, `audit()`, `cleanup_outbox()`, `cleanup_expired_rows()`. |
| `auth.rs` | Нормализация email, контекстные OTP/recovery-хеши, сессии, rate limit, IP/UA; failed-attempt counters advisory. |
| `email.rs` | `EmailSender`: outbox или SMTP через `lettre`; таймаут 10 секунд, redaction outbox. |
| `state.rs` | `AppState`, challenge maps, `cleanup_expired()`, `RateLimiter`. |
| `routes.rs` | Все HTTP handlers, ceremony cookie, admin server-side sessions, step-up, сборка router. |
| `error.rs` | `AppError` (`StepUpRequired` и др.) → JSON; hard-lockout error удалён. |

## 2. Модель данных

Схема — `0001_init.sql` + `0002_security_hardening.sql` + `0003_legacy_and_cookie.sql`.
Все ID — UUID v4 в `TEXT`, кроме `audit_events.id` (integer autoincrement). Время —
RFC3339 UTC в `TEXT`.

| Таблица | Ключевые колонки | Назначение |
|---|---|---|
| `users` | `id` PK, `email` UNIQUE, `status`, `failed_attempts`, `locked_until`, `created_at` | Пользователь. Пароля нет. `status` проверяется при валидации сессии. `failed_attempts` — advisory для алертов; `locked_until` не используется (hard lockout удалён). |
| `otp_codes` | `id`, `user_id` FK, `purpose`, `code_hash`, `attempts`, `created_at`, `expires_at`, `used_at` | Одноразовые email-коды. `purpose` — `login` или `recovery`. Хеш привязан к user/purpose/id/expiry; max 5 попыток. |
| `passkeys` | `id`, `user_id` FK, `credential_id` UNIQUE, `data`, `counter`, `label`, `created_at`, `last_used_at` | WebAuthn-passkey. `data` — сериализованный `Passkey`; `counter` — отдельная колонка для regression policy. Приватный ключ сюда не попадает. |
| `sessions` | `id`, `user_id` FK, `token_hash` UNIQUE, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ip`, `user_agent`, `passkey_id`, `stepup_at` | Серверные сессии; SHA-256-хеш токена, привязка к passkey и время step-up. Legacy-сессии с NULL `passkey_id` отозваны в 0003. |
| `recovery_codes` | `id`, `user_id` FK, `code_hash`, `created_at`, `expires_at`, `used_at` | 8 одноразовых recovery-кодов с TTL; новые коды имеют `expires_at` и контекстный HMAC. Legacy `NULL expires_at` инвалидированы в 0003 (`expires_at=1970...`). Счётчики/проверка последнего credential фильтруют `used_at` и `expires_at`. |
| `admin_sessions` | `id` PK, `token_hash` UNIQUE, `created_at`, `expires_at`, `ip`, `user_agent`, `revoked_at` | Серверные admin-сессии: opaque token hash, TTL 1 час, logout ставит `revoked_at`. |
| `outbox` | `id`, `to_email`, `subject`, `body`, `created_at` | Письма. Body содержит OTP только в `DEV_MODE=true` + `EMAIL_PROVIDER=outbox`; при SMTP — redacted. Записи старше 1 дня удаляются. |
| `audit_events` | `id` INTEGER PK, `user_id`, `event`, `ip`, `user_agent`, `metadata`, `created_at` | Аудит. `user_id` без FK, `metadata` — JSON-строка. |

Индексы:

- `otp_codes(user_id, purpose, used_at)`;
- `passkeys(user_id)`;
- `sessions(user_id, revoked_at)`;
- `sessions(user_id, passkey_id, revoked_at)`;
- `recovery_codes(user_id, used_at)`;
- `recovery_codes(user_id, used_at, expires_at)`;
- `admin_sessions(expires_at, revoked_at)`;
- `audit_events(created_at)`.

`outbox` индекса по `created_at` не имеет: очистка старше 1 дня и dev outbox сортируют
полной выборкой/сканом.

### 2.1. Хеши и секреты

| Данные | Формула | Где хранится |
|---|---|---|
| Секрет OTP/recovery | `SHA-256(OTP_SECRET)` → 32 байта; в dev может быть случайным, вне dev обязателен | В памяти процесса |
| OTP-код | `HMAC-SHA-256(secret, "otp:v1:{user_id}:{purpose}:{otp_id}:{expires_at}:{code}")` → hex | `otp_codes.code_hash` |
| Recovery-код | Новые: `HMAC-SHA-256(secret, "recovery:v1:{user_id}:{code_id}:{expires_at}:{code}")`; legacy NULL-expiry rows инвалидированы в 0003. Код сохраняет defensive fallback на старый global-HMAC, но такие строки не должны оставаться валидными | `recovery_codes.code_hash` |
| Session-токен | `SHA-256(token)` → hex | `sessions.token_hash` |
| Admin session token | `SHA-256(token)` → hex; opaque token в cookie | `admin_sessions.token_hash` |
| Passkey | Публичный ключ и metadata в JSON | `passkeys.data` |
| SMTP credentials | `SecretString` в памяти; в БД не хранятся | env → процесс, debug-вывод redacted |

OTP/recovery-хеши привязаны к пользователю, purpose/ID и expiry, поэтому одинаковый код
в другом контексте не подойдёт. `normalize(code)` для recovery: убрать дефисы и пробелы,
привести к верхнему регистру.
Поэтому recovery-код можно вводить с дефисами или без, в любом регистре.

Проверка OTP и recovery-кодов использует `constant_time_eq`. Проверка session-токена —
обычный поиск по индексу `token_hash`; при 256 битах энтропии timing-атака на сравнение
непрактична.

**Паролей нет ни в одной таблице.** Нет password hash, password reset, «секретного
вопроса» и endpoint'а смены пароля. Долгоживущие секреты пользователя — это passkey
(private key у authenticator) и recovery-коды (только хеши в БД).

### 2.2. Особенности хранения

- `passkeys.data` — JSON целиком, а отдельная колонка `counter` хранит счётчик для
  regression policy. При входе JSON десериализуется; `counter` обновляется отдельно.
- `credential_id` хранится отдельно в base64url без padding для UNIQUE-проверки и поиска.
- Даты — строки RFC3339. SQL-сравнения (`expires_at > ?`) лексикографические. Все значения
  в UTC с одним offset, поэтому в обычном случае это работает; на границе секунды с
  дробной частью возможны редкие неточности. Для строгой корректности лучше хранить
  epoch integer или использовать `DATETIME` SQLite.
- `ON DELETE CASCADE` объявлен для `otp_codes`, `passkeys`, `sessions`,
  `recovery_codes`; `db::init` включает `PRAGMA foreign_keys=ON`. Endpoint'а удаления
  пользователя всё равно нет.
- SQLite открывается с WAL, foreign keys и busy timeout 5s (`db::init`).
- Транзакции: `create_otp` атомарно пишет `otp_codes` + `outbox` и коммитит до отправки
  письма; `create_recovery_codes` атомарно заменяет batch; `passkey_register` атомарно
  пишет passkey + session + recovery-коды; `recover_verify_code` атомарно отзывает все
  сессии и удаляет все passkeys; `revoke_passkey` атомарно удаляет passkey и отзывает
  привязанные сессии. `verify_otp` и `verify_recovery_code` используют условный
  `UPDATE ... WHERE used_at IS NULL` и проверяют `rows_affected`.
- `passkey_add_finish` делает одиночный INSERT. Остаются нетранзакционные участки:
  проверка дубликата credential перед INSERT и связка «recovery-код + in-memory challenge».
- Cleanup: outbox старше 1 дня; `otp_codes`, `sessions`, `recovery_codes` (включая NULL/expired),
  `admin_sessions` (expired/revoked) чистятся при старте и раз в 300 секунд.
  `audit_events` автоматически не удаляются.
- `DATABASE_URL` логируется через `redacted_db_url()`: query-параметры и userinfo скрываются.

### 2.3. Обновление и 0003

`0003_legacy_and_cookie.sql`:

- `UPDATE recovery_codes SET expires_at='1970...' WHERE expires_at IS NULL` — legacy
  recovery-коды без срока инвалидируются;
- `UPDATE sessions SET revoked_at='1970...' WHERE passkey_id IS NULL` — legacy-сессии без
  passkey binding принудительно отзываются;
- `ALTER TABLE passkeys ADD COLUMN counter` — отдельный счётчик для regression policy;
- создаёт `admin_sessions` (opaque token hash, TTL, logout revocation).

После обновления пользователи должны перелогиниться, а recovery-коды — перегенерировать.
Старые HMAC admin-cookie недействительны; нужен новый `/admin/login`. Существующие
passkeys получают `counter=0`: до counter backfill или перерегистрации clone detection
ослаблен на одну assertion (R3-2). Перед миграцией сделайте backup.

## 3. Состояние в памяти

`AppState` хранит четыре `Arc<Mutex<HashMap<...>>>` и rate limiter. Всё это живёт только
в процессе; раз в 300 секунд вызывается `cleanup_expired()`.

| Map | Структура | TTL | Создаётся | Потребляется |
|---|---|---|---|---|
| `auth_challenges` | `AuthChallenge { user_id, PasskeyAuthentication, expires_at }` | 2 минуты | `POST /api/auth/start`, если у пользователя есть passkey | `POST /api/auth/passkey/login` |
| `reg_challenges` | `RegChallenge { user_id, PasskeyRegistration, expires_at }` | 2 минуты после `verify-code` и `passkeys/add/start`; 5 минут после `recover/verify-code` | `verify-code`, `recover/verify-code`, `passkeys/add/start` | `passkey/register` или `passkeys/add/finish` |
| `stepup_challenges` | `AuthChallenge { user_id, PasskeyAuthentication, expires_at }` | 2 минуты | `POST /api/auth/stepup/start` | `POST /api/auth/stepup/finish` |
| `recovery_challenges` | `RecoveryChallenge { user_id, email, expires_at }` | 10 минут | `POST /api/auth/recover/verify-email` | `POST /api/auth/recover/verify-code` |
| `rate_limiter` | `HashMap<String, Vec<Instant>>` | Окно 60/300 секунд; очистка до 1 часа / 10k ключей | См. 3.4 | Те же handlers |

### 3.1. Одноразовость

Challenge забирается из map через `remove()` **до** проверки срока и криптографии.
Исключения: `passkeys/add/finish` и `stepup/finish` сначала проверяют, что challenge
принадлежит текущему пользователю; при несовпадении возвращается `challenge_not_found`
и challenge не удаляется. Следствия:

- успешная церемония удаляет challenge;
- неудачная церемония тоже удаляет challenge;
- повторный вызов с тем же `challenge_id` вернёт `challenge_not_found`;
- просроченный challenge удаляется только при попытке использования.

`challenge_id` — UUID v4, возвращается клиенту в JSON. Для login/registration/recovery
он не привязан к IP или User-Agent, но **все** WebAuthn/recovery/add-passkey/step-up
challenge дополнительно связаны с HttpOnly `SameSite=Strict` cookie **`al_ceremony`**
(10 минут): сервер выставляет её вместе с `challenge_id`, а finish/verify проверяют
совпадение. Ручной API-клиент обязан сохранять эту cookie. Считайте `challenge_id` и
`al_ceremony` секретами на время TTL.

### 3.2. Рестарт и несколько инстансов

- Рестарт процесса очищает все in-memory challenge maps: незавершённые WebAuthn/recovery/
  step-up-церемонии становятся невалидными.
- OTP-коды, сессии и recovery-коды лежат в SQLite и переживают рестарт, **если
  `OTP_SECRET` стабилен**. При случайном секрете старые OTP/recovery-хеши перестают
  совпадать.
- Второй инстанс не увидит challenge первого. Для нескольких инстансов нужны общий
  store (Redis/БД) или sticky sessions.

### 3.3. Очистка и границы

- Challenge maps и rate limiter очищаются раз в 300 секунд: просроченные challenge
  удаляются, размер maps ограничен 10 000, rate limiter — 10 000 ключей / 1 час.
- Очистка не делает состояние общим: второй инстанс не увидит challenge первого, а
  рестарт всё равно прерывает незавершённые церемонии.
- `outbox` чистится от записей старше 1 дня; `otp_codes`, `sessions`, `recovery_codes`
  (включая NULL/expired) и `admin_sessions` (expired/revoked) — `cleanup_expired_rows()`
  при старте и раз в 300 секунд. `audit_events` автоматически не удаляются.

### 3.4. Rate limits

| Endpoint | Лимит |
|---|---|
| `POST /api/auth/start` | 5/60 на email, 30/60 на IP |
| `POST /api/auth/verify-code` | 10/60 на email, 20/60 на IP |
| `POST /api/auth/passkey/register` | 20/60 на IP |
| `POST /api/auth/passkey/login` | 20/60 на IP |
| `POST /api/auth/passkeys/add/start` | 20/60 на IP |
| `POST /api/passkeys/add/finish` | 20/60 на IP |
| `POST /api/auth/stepup/start` | 20/60 на IP |
| `POST /api/auth/stepup/finish` | 20/60 на IP |
| `POST /api/auth/recover/start` | 3/300 на email, 20/300 на IP |
| `POST /api/auth/recover/verify-email` | 5/60 на email, 10/60 на IP |
| `POST /api/auth/recover/verify-code` | 5/60 на email (если challenge найден), 10/60 на IP |
| `POST /admin/login` | 5/60 на IP |

Лимиты in-memory и per-process: рестарт их сбрасывает, несколько инстансов их не делят.
List/revoke/regenerate/admin-page лимитов не имеют (admin login — имеет).

## 4. Потоки

### 4.1. Первый вход и регистрация passkey

Предусловие: пользователя нет или у него ещё нет passkey.

**Шаг 1. Начало входа**

```http
POST /api/auth/start
Content-Type: application/json

{"email":"user@example.com"}
```

Что делает handler:

1. `check_origin`: в production `Origin` обязателен и должен совпадать с `APP_URL`;
   отсутствие/несовпадение — 403 `forbidden`. В `DEV_MODE` отсутствие `Origin` разрешено.
2. `normalize_email`: trim, lowercase, длина 3–254, есть `@`, нет пробелов, непустые
   local/domain. Ошибка — 400 `invalid_email`.
3. Rate limit: `start:email:{email}` — 5 запросов / 60 секунд; `start:ip:{ip}` —
   30 / 60 секунд. Превышение — 429 `too_many_requests`.
4. Поиск пользователя по email.
5. Если пользователь найден и неактивен — возвращается generic `flow: "code"` без OTP
   (аудит `auth_start_inactive`), чтобы не раскрывать статус.
6. Если пользователь активен и у него есть passkey — запускается passkey-вход
   (раздел 4.2), возвращается `flow: "passkey"`; сервер также ставит HttpOnly
   `SameSite=Strict` cookie `al_ceremony` с `challenge_id` (10 минут).
7. Иначе `ensure_user`: пользователь создаётся со `status='active'`, если его не было.
8. `create_otp(purpose="login")`: генерируется 6-значный код; в одной транзакции пишутся
   контекстный HMAC-хеш в `otp_codes` и письмо в `outbox`; затем `EmailSender`:
   `outbox` — no-op, `smtp` — реальная отправка с таймаутом 10 секунд. Тело outbox
   содержит код только при `DEV_MODE=true` + `EMAIL_PROVIDER=outbox`, иначе redacted.
   TTL — `OTP_TTL_MINUTES`. Если SMTP-отправка падает после коммита, handler возвращает
   500 (`internal_error`), а пользователь должен запросить новый код.
9. Аудит: `user_created` или `otp_sent`, metadata `{"email":"..."}`.
10. Ответ:

```json
{"flow":"code","email":"user@example.com","dev_outbox":"/dev/outbox"}
```

При `DEV_MODE=false` поле `dev_outbox` равно `null`. При `EMAIL_PROVIDER=smtp` письмо
отправляется, но запись в `outbox` остаётся с redacted body; кода в ней нет.
При `EMAIL_PROVIDER=outbox` письмо не отправляется, и `/dev/outbox` — единственный способ
получить код (только при `DEV_MODE=true`).

**Шаг 2. Проверка email-кода**

```http
POST /api/auth/verify-code
Content-Type: application/json

{"email":"user@example.com","code":"123456"}
```

1. `check_origin`, `normalize_email`.
2. Rate limit: `verify-code:email:{email}` — 10/60; `verify-code:ip:{ip}` — 20/60.
   Превышение — 429.
3. Поиск пользователя. Если нет или пользователь неактивен — 400 `invalid_code`
   (generic, без раскрытия статуса).
4. `verify_otp` берёт **последний** код для `user_id + purpose='login'`:
   - нет кода — `code_not_found`;
   - `used_at` уже стоит — `code_already_used`;
   - `attempts >= 5` — `too_many_attempts`;
   - истёк `expires_at` — `code_expired`;
   - хеш не совпал — `invalid_code`; attempts резервируется атомарно, `failed_attempts`
     увеличивается только для алертов (hard lockout нет);
   - успех — `used_at = now` (условный UPDATE, защищает от concurrent replay).
5. После успешной проверки загружаются passkeys. Если они есть — 400 `use_passkey`:
   email-код не является fallback для пользователей с passkey.
6. `start_passkey_registration(user_id, email, email, None)` создаёт WebAuthn-опции.
7. В `reg_challenges` кладётся challenge с TTL 2 минуты; сервер ставит HttpOnly
   `SameSite=Strict` cookie `al_ceremony` с `challenge_id` (10 минут).
8. Аудит `otp_verified`.
9. Ответ:

```json
{"flow":"register_passkey","challenge_id":"...","options":{...}}
```

Сессия на этом шаге ещё не создаётся. OTP уже помечен использованным: если регистрация
passkey не удастся, код повторно не сработает — нужен новый `start`/`verify-code`.

**Шаг 3. Завершение регистрации passkey**

```http
POST /api/auth/passkey/register
Content-Type: application/json

{"challenge_id":"...","credential":{...}}
```

1. `check_origin`; rate limit `passkey-register:ip:{ip}` — 20/60.
2. Проверка `al_ceremony`: cookie должна совпадать с `challenge_id`, иначе
   400 `challenge_not_found`.
3. `challenge_id` забирается из `reg_challenges`; нет — 400 `challenge_not_found`.
4. Проверка `expires_at`; истёк — 400 `challenge_expired`.
5. Проверка `is_active_user`; неактивен — 400 `registration_failed`.
6. `credential` десериализуется в `RegisterPublicKeyCredential`. Ошибка serde отдаётся
   как 400 `bad_request` с текстом ошибки в `message`.
7. `finish_passkey_registration` проверяет WebAuthn-ответ. Ошибка библиотеки —
   400 `webauthn_error`.
8. `credential_id` кодируется в base64url. Если такой credential уже есть —
   400 `credential_already_registered`.
9. Passkey сохраняется в `passkeys` (`counter=0`); label определяется по User-Agent
   (`Windows passkey`, `iPhone passkey` и т.п.).
10. Создаётся сессия: 32 случайных байта, в БД — SHA-256-хеш, `passkey_id` этого passkey,
    клиенту — cookie.
11. Если это первый passkey пользователя, генерируются 8 recovery-кодов с TTL
    `RECOVERY_CODE_TTL_DAYS`; в БД — HMAC-хеши, в ответе — открытые коды. Иначе пустой массив.
    Шаги 9–11 выполняются в одной транзакции.
12. Аудит `passkey_registered` с `{"first_passkey": true|false}`.
13. Ответ + `Set-Cookie`:

```json
{"ok":true,"recovery_codes":["ABCD-EFGH-IJKL","..."]}
```

Cookie:

```text
Set-Cookie: __Host-al_session=<43 символа base64url>; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=604800
```

В production имя `__Host-al_session` и `Secure` обязательны; в dev/HTTP — `al_session`
без `Secure` (non-dev такие настройки отклоняются). `Max-Age` равен
`SESSION_TTL_DAYS * 86400`. Ceremony cookie `al_ceremony` очищается при успешном finish.

**Записи в БД:** `users` (возможно), `otp_codes`, `outbox`, `passkeys`, `sessions`,
`recovery_codes`. OTP+outbox коммитятся в `create_otp`; passkey+session+recovery-коды —
одной транзакцией на шаге 3. Аудит пишется отдельно, best-effort.

### 4.2. Вход по passkey

Предусловие: пользователь существует и у него есть хотя бы один passkey.

**Шаг 1. Начало входа**

```http
POST /api/auth/start
{"email":"user@example.com"}
```

Если пользователь найден и passkey есть:

1. `start_passkey_authentication(&passkeys)` строит опции со списком допустимых
   credential.
2. В `auth_challenges` кладётся challenge с TTL 2 минуты; ставится cookie
   `al_ceremony` с `challenge_id` (HttpOnly/Strict/Secure по конфигу, 10 минут).
3. Аудит `auth_start_passkey`.
4. Ответ:

```json
{"flow":"passkey","challenge_id":"...","options":{...}}
```

Если пользователя нет или passkey нет — выполняется OTP-ветка из 4.1. То есть страница
входа может использоваться и для первого входа.

**Шаг 2. Завершение входа**

```http
POST /api/auth/passkey/login
{"challenge_id":"...","credential":{...}}
```

1. `check_origin`; rate limit `passkey-login:ip:{ip}` — 20/60.
2. Проверка `al_ceremony` по `challenge_id`; несовпадение — `challenge_not_found`.
3. Challenge забирается из `auth_challenges`; нет — `challenge_not_found`, истёк —
   `challenge_expired`.
4. `is_active_user`; неактивен — 401 `unauthenticated`.
5. `credential` десериализуется в `PublicKeyCredential`.
6. `finish_passkey_authentication` проверяет подпись, origin, RP ID, challenge.
7. Passkey ищется по `user_id` из challenge и `credential_id` из результата.
   Нет — 400 `passkey_not_found`.
8. Counter policy: если `stored_counter > 0 && asserted_counter <= stored_counter` —
   400 `passkey_counter_regression` + audit; synced 0/0 допускается с audit
   `passkey_synced_counter_zero`. `passkeys.counter` и `last_used_at` обновляются.
9. Создаётся сессия с `passkey_id`, ставится cookie; `al_ceremony` очищается.
10. Аудит `passkey_login` с `{"passkey_id":"..."}`.
11. Ответ: `{"ok":true}` + `Set-Cookie`.

Email-код в этом flow не участвует. Если passkey-церемония не удалась, fallback на email
для пользователя с passkey в v0.1 нет.

### 4.3. Восстановление

Используется, когда passkey потерян, но есть неиспользованный recovery-код.

**Шаг 1. Начало восстановления**

```http
POST /api/auth/recover/start
{"email":"user@example.com"}
```

1. `check_origin`, `normalize_email`.
2. Rate limit: `recover:email:{email}` — 3/300 и `recover-start:ip:{ip}` — 20/300.
3. Поиск пользователя. Если пользователь отсутствует или неактивен, OTP не создаётся,
   пишется audit (`recovery_start_unknown`/`recovery_start_inactive`), но ответ всё равно
   generic — наличие аккаунта не раскрывается.
4. Для активного пользователя `create_otp(purpose="recovery")`: OTP+outbox в одной
   транзакции, затем отправка. Если `create_otp` вернул ошибку (доставка или БД), пишется
   `recovery_start_delivery_failed`, но handler не возвращает ошибку.
5. При успехе — audit `recovery_started` и security notification на email.
6. Ответ всегда generic: `{"flow":"code","email":"...","dev_outbox":"/dev/outbox"}`.

**Шаг 2. Проверка email-кода**

```http
POST /api/auth/recover/verify-email
{"email":"user@example.com","code":"123456"}
```

1. `check_origin`, `normalize_email`, поиск пользователя.
2. Rate limit `recover-verify-email:email:{email}` — 5/60; `recover-verify-email:ip:{ip}` — 10/60.
3. Неизвестный/неактивный пользователь — generic 400 `invalid_code` с audit.
4. `verify_otp(purpose="recovery")` — 5 попыток на OTP, `failed_attempts` advisory;
   hard lockout нет.
5. Создаётся `RecoveryChallenge { user_id, email, expires_at }` с TTL 10 минут;
   возвращается `challenge_id`; сервер ставит `al_ceremony` cookie с `challenge_id`.
6. Аудит `recovery_email_verified`.
7. Ответ:

```json
{"flow":"recovery_code","challenge_id":"..."}
```

**Шаг 3. Проверка recovery-кода**

```http
POST /api/auth/recover/verify-code
{"challenge_id":"...","recovery_code":"ABCD-EFGH-IJKL"}
```

1. `check_origin`; rate limits `recover-verify-code:ip:{ip}` — 10/60 и
   `recover-verify-code:email:{email}` — 5/60 (email берётся из challenge, если он найден).
2. Проверка `al_ceremony` по `challenge_id`; несовпадение — `challenge_not_found`.
3. `RecoveryChallenge` забирается из map; нет — `challenge_not_found`, истёк —
   `challenge_expired`.
4. `verify_recovery_code` выбирает только
   `used_at IS NULL AND (expires_at IS NULL OR expires_at > now)` и сравнивает HMAC
   constant-time. Для `expires_at IS NOT NULL` используется контекстный
   `recovery:v1`-хеш; для legacy `NULL expires_at` остаётся defensive fallback на старый
   global-HMAC, но миграция 0003 инвалидирует такие строки. При совпадении делается
   условный `UPDATE ... WHERE used_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
   с проверкой `rows_affected`; ошибка/несовпадение увеличивает `failed_attempts`
   (advisory, без lockout).
5. Если код не найден/истёк/уже использован — 400 `invalid_recovery_code`. Challenge
   к этому моменту уже удалён: повторная попытка требует нового email-кода.
6. При успехе в одной транзакции отзываются **все** сессии пользователя и удаляются
   **все** passkeys; audit `recovery_credentials_revoked`, security notification на email.
7. Загружается email пользователя, запускается `start_passkey_registration`.
8. В `reg_challenges` кладётся challenge с TTL 5 минут; сервер ставит новый
   `al_ceremony` cookie для регистрации.
9. Аудит `recovery_code_verified`.
10. Ответ:

```json
{"flow":"register_passkey","challenge_id":"...","options":{...}}
```

**Шаг 4. Новый passkey**

`POST /api/auth/passkey/register` с полученным `challenge_id` — тот же handler, что в 4.1.
Создаётся сессия. Если после регистрации у пользователя ровно один passkey, возвращаются
8 новых recovery-кодов; старые неиспользованные коды при этом удаляются.

**Особенности recovery в v0.1:**

- успешный recovery отзывает **все** сессии и удаляет **все** passkeys пользователя;
  после этого обязательна регистрация нового passkey;
- recovery-код одноразовый и живёт `RECOVERY_CODE_TTL_DAYS` (по умолчанию 365 дней);
  на один recovery-challenge даётся одна попытка, плюс per-email/per-IP rate limits;
  hard lockout нет, `failed_attempts` только для алертов;
- legacy NULL-expiry коды инвалидируются миграцией 0003, поэтому после обновления
  нужны новые recovery-коды;
- если неиспользованных/неистёкших recovery-кодов нет, восстановление невозможно;
- на email отправляется security notification о начале и завершении recovery
  (best-effort, через выбранный email provider).

### 4.4. Валидация сессии

Функции `current_session` и `require_session` в `routes.rs` вызываются каждым handler'ом
отдельно; глобального middleware нет.

Алгоритм `session_from_token`:

1. Взять значение cookie с именем `COOKIE_NAME`. Нет cookie — `None`.
2. `token_hash = SHA-256(token)` (hex).
3. `SELECT s.id, s.user_id, s.expires_at, s.revoked_at, s.last_seen_at,
   s.passkey_id, s.stepup_at, u.email, u.status` из `sessions JOIN users` по `s.token_hash`.
4. Нет строки — `None`.
5. `revoked_at IS NOT NULL` или `users.status != 'active'` — `None`.
6. `now > expires_at` — `None` (абсолютный TTL).
7. `now - last_seen_at > SESSION_IDLE_HOURS` — `None` (idle timeout).
8. `UPDATE sessions SET last_seen_at = now`.
9. Вернуть `SessionUser { session_id, user_id, email, expires_at, passkey_id, stepup_at }`.

`require_session` превращает `None` в 401 `unauthenticated`. `require_stepup` отдельно
проверяет `stepup_at` для чувствительных handlers.

Что **не** делает валидация:

- не продлевает `expires_at` и не обновляет cookie;
- не делает rotation;
- не проверяет привязку к устройству/IP/UA (но passkey-сессии хранят `passkey_id`,
  а step-up проверяется отдельно);
- не проверяет CSRF-токен;
- не проверяет `Origin` на GET.

Cookie остаётся валидной до `Max-Age`, но серверные `expires_at` и idle timeout —
источник истины. `SameSite=Strict`; в production имя `__Host-al_session` и `Secure`
обязательны, `al_session` допускается только в dev/HTTP. Legacy-сессии с NULL
`passkey_id` отозваны миграцией 0003.

`GET /api/me` использует `current_session` и при отсутствии сессии возвращает
`{"authenticated":false}` с 200. `recovery_codes_remaining` считает только
`used_at IS NULL AND (expires_at IS NULL OR expires_at > now)`; истёкшие коды не
учитываются. Остальные защищённые endpoint'ы возвращают 401.

### 4.5. Logout

```http
POST /api/auth/logout
```

1. `check_origin`; в production `Origin` обязателен.
2. Если cookie валидна — `revoke_session` ставит `revoked_at` для текущей сессии.
3. Аудит `logout`.
4. Cookie очищается (`Max-Age=0`, пустое значение, те же атрибуты).
5. Ответ `{"ok":true}` даже если сессии не было.

`revoke_session` возвращает `true/false` по `rows_affected`. Logout не проверяет результат;
`POST /api/sessions/{id}/revoke` проверяет и отдаёт 404 для неизвестного/чужого ID.

### 4.6. Admin

Admin больше не принимает токен в query string.

**Вход**

```http
GET  /admin/login
POST /admin/login
```

1. Если `ADMIN_TOKEN` не задан — 404.
2. `GET /admin/login` показывает форму; при валидной admin-session редиректит на `/admin`.
3. `POST /admin/login` принимает `token` как form-urlencoded или JSON `{"token":"..."}`,
   проверяет rate limit `admin-login:ip:{ip}` — 5/60 и сравнивает `ADMIN_TOKEN`
   constant-time.
4. Неверный токен — 403 `forbidden`; audit `admin_login_failed`.
5. Успех — генерируется opaque admin token, в БД в `admin_sessions` пишется его
   SHA-256-хеш, TTL 1 час; cookie `al_admin` содержит opaque token (не HMAC),
   `HttpOnly`, `SameSite=Strict`, `Secure` по конфигу, `Path=/admin`, `Max-Age=1 час`.
   Audit `admin_login_success`.

**Просмотр**

```http
GET /admin
```

1. Без валидной `admin_sessions` записи (cookie token hash, not revoked/expired) —
   redirect на `/admin/login`.
2. С валидной cookie — read-only страница: последние 200 пользователей, 200 сессий и
   100 audit-событий; audit `admin_view`.
3. Действий нет.

**Выход**

```http
POST /admin/logout
```

Ставит `revoked_at` для admin-сессии в БД, очищает cookie, пишет audit `admin_logout`
и редиректит на `/admin/login`.

Особенности: admin login ограничен по IP; admin-сессия живёт 1 час и отзывается logout;
старые HMAC admin-cookie недействительны; отдельные admin-аккаунты, роли и 2FA отсутствуют.

### 4.7. Dev outbox

`GET /dev/outbox` и `GET /api/dev/outbox` доступны только при `DEV_MODE=true`, иначе 404.

- Возвращают последние 50 записей из `outbox` по убыванию `created_at`.
- HTML-версия обновляется каждые 5 секунд.
- `outbox` пишется в обоих режимах. Тело содержит OTP только при
  `DEV_MODE=true` + `EMAIL_PROVIDER=outbox`; при SMTP body редактируется
  (`One-time code generated and sent by email.`), кода в нём нет.
- Записи старше 1 дня удаляются при старте и раз в 300 секунд; `cleanup_expired_rows`
  также чистит OTP/sessions/recovery/admin_sessions.
- HTML-страница содержит статичный текст «Email is not sent in dev mode», который
  неточен при SMTP: письмо отправляется, но в outbox только redacted-запись.

### 4.8. Добавление passkey к текущей сессии

Требуется действующая cookie **и свежий step-up**. Новый passkey добавляется к тому же
пользователю; новая сессия не создаётся, recovery-коды не выдаются. Challenge живёт
2 минуты и привязан к текущему пользователю.

**Шаг 1. Начать**

```http
POST /api/passkeys/add/start
```

1. `check_origin`; rate limit `passkey-add-start:ip:{ip}` — 20/60.
2. `require_session` — без сессии 401; `require_stepup` — без свежего step-up
   403 `stepup_required`.
3. Загружаются существующие passkeys; их `credential_id` передаются в
   `start_passkey_registration(..., Some(exclude))`, чтобы не предложить уже сохранённый
   credential.
4. В `reg_challenges` кладётся `RegChallenge { user_id, state, expires_at }` с TTL 2 минуты;
   ставится `al_ceremony` cookie с `challenge_id`.
5. Аудит `passkey_add_started`.
6. Ответ:

```json
{"challenge_id":"...","options":{...}}
```

**Шаг 2. Завершить**

```http
POST /api/passkeys/add/finish
{"challenge_id":"...","credential":{...}}
```

1. `check_origin`; rate limit `passkey-add-finish:ip:{ip}` — 20/60.
2. `require_session` — без сессии 401; `require_stepup` — 403 `stepup_required`.
3. Проверка `al_ceremony` по `challenge_id`; несовпадение — `challenge_not_found`.
4. Challenge ищется по `challenge_id`; если его нет или `challenge.user_id` не совпадает
   с текущим пользователем — 400 `challenge_not_found` (при несовпадении challenge
   не удаляется).
5. Проверка `expires_at`; истёк — `challenge_expired`.
6. `credential` десериализуется, `finish_passkey_registration` проверяет WebAuthn-ответ.
7. Проверка дубликата `credential_id`; затем INSERT в `passkeys` (`counter=0`).
8. Аудит `passkey_added`; `al_ceremony` очищается.
9. Ответ: `{"ok":true}`. Cookie и `passkey_id` текущей сессии не меняются.

Ошибки: `stepup_required`, `challenge_not_found`, `challenge_expired`,
`credential_already_registered`, `webauthn_error`, 401 `unauthenticated`.
UI использует этот flow через step-up.

### 4.9. Healthcheck

`GET /healthz` выполняет `SELECT 1`:

- успех — 200, JSON `{"ok":true,"service":"authlayer","version":"...","dev_mode":...}`;
- ошибка БД — 503, JSON `{"ok":false,"service":"authlayer","version":"...","dev_mode":...,"error":"database_unavailable"}`.

Ответ не использует формат `AppError`. `Cache-Control: no-store` добавляется и к нему.

### 4.10. Step-up

```http
POST /api/auth/stepup/start
POST /api/auth/stepup/finish
```

1. Оба endpoint'а требуют действующую cookie; rate limit 20/60 на IP.
2. `stepup/start` загружает passkeys; если их нет — 400 `no_passkeys`; создаёт
   `stepup_challenges` с TTL 2 минуты, ставит `al_ceremony` cookie и возвращает
   `{challenge_id, options}`.
3. `stepup/finish` проверяет `al_ceremony`, что challenge принадлежит текущему
   пользователю, и выполняет WebAuthn assertion. При успехе обновляет
   `sessions.stepup_at` и очищает ceremony cookie.
4. `stepup_at = now`; `require_stepup` принимает только `0 <= now - stepup_at <= 5 минут`.
   Future-dated legacy-значения (`stepup_at > now`) отклоняются. В ответе
   `stepup_until = now + 5 минут` — это граница окна, не отдельное состояние.
5. Ответ: `{"ok":true,"stepup_until":"..."}`.

Step-up требуется для `passkeys/add/*`, `passkeys/{id}/revoke`, `recovery/regenerate`,
`sessions/revoke-all`. Без него — 403 `stepup_required`.

### 4.11. Revoke-all и удаление passkey

- `POST /api/sessions/revoke-all` требует step-up, ставит `revoked_at` всем активным
  сессиям пользователя, пишет audit `sessions_revoked_all` и очищает текущую cookie.
- `POST /api/passkeys/{id}/revoke` требует step-up, в одной транзакции удаляет passkey,
  проверяет, что остался хотя бы один credential или неистёкший recovery-код
  (`used_at IS NULL AND (expires_at IS NULL OR expires_at > now)`), и отзывает сессии,
  привязанные к удалённому `passkey_id`. Если текущая сессия была привязана к нему,
  cookie очищается. Неизвестный/чужой ID — 404.
- `POST /api/recovery/regenerate` требует step-up, атомарно заменяет 8 кодов с TTL
  `RECOVERY_CODE_TTL_DAYS` и отправляет security notification.

## 5. Ошибки

### 5.1. Формат

```json
{"error":"bad_request","message":"invalid_code"}
```

`error` — стабильная категория, `message` — человекочитаемое или машинное пояснение.

| `AppError` | HTTP | `error` | `message` |
|---|---:|---|---|
| `BadRequest(msg)` | 400 | `bad_request` | Переданный код, например `invalid_code` |
| `Unauthorized` | 401 | `unauthenticated` | `Authentication required` |
| `Forbidden` | 403 | `forbidden` | `Access denied` |
| `NotFound` | 404 | `not_found` | `Resource not found` |
| `TooManyRequests` | 429 | `too_many_requests` | `Too many requests. Try again later.` |
| `StepUpRequired` | 403 | `stepup_required` | `Additional authentication required` |
| `Webauthn(msg)` | 400 | `webauthn_error` | Текст ошибки `webauthn-rs` |
| `Internal(msg)` | 500 | `internal_error` | `Internal server error`; реальная ошибка пишется в лог |

Для `400 bad_request` клиенту нужно смотреть на `message`: именно там лежит машинный код.
Для остальных статусов можно ориентироваться на `error`. `404 not_found` теперь также
возвращается revoke-endpoint'ами для неизвестного или чужого ID. `403 stepup_required`
означает, что нужен `POST /api/auth/stepup/*`. Hard account lockout удалён;
`failed_attempts` - advisory. SMTP-сбой после коммита OTP возвращает `500 internal_error`;
`recover/start` при ошибке доставки не отдаёт 500, а логирует
`recovery_start_delivery_failed` и возвращает generic-ответ.

### 5.2. Коды в `message`

| `message` | Где появляется | Смысл |
|---|---|---|
| `invalid_email` | `start`, `verify-code`, `recover/start`, `recover/verify-email` | Email не прошёл простую валидацию. |
| `invalid_code` | `verify-code`, `recover/verify-email` | Неверный/истёкший код **или** неизвестный/неактивный пользователь (generic, чтобы уменьшить enumeration); при неверном хеше увеличивается `failed_attempts`. |
| `use_passkey` | `verify-code` | Код верный, но у пользователя уже есть passkey; email-код не fallback. |
| `registration_failed` | `passkey/register` | Пользователь стал неактивен до завершения регистрации. |
| `no_passkeys` | `stepup/start` | У пользователя нет passkey для step-up. |
| `invalid_request` | `admin/login` | Не передан `token` в form/JSON. |
| `code_not_found` | Проверка OTP | Для `user_id + purpose` нет кода. |
| `code_already_used` | Проверка OTP | Код уже использован. |
| `too_many_attempts` | Проверка OTP | `attempts >= 5`. |
| `code_expired` | Проверка OTP | `expires_at` в прошлом. |
| `challenge_not_found` | `passkey/register`, `passkey/login`, `stepup/finish`, `passkeys/add/finish`, `recover/verify-code` | Нет такого `challenge_id` (или уже использован), либо несовпадение `al_ceremony`; для add/step-up — также чужой пользователь. |
| `challenge_expired` | Те же | TTL challenge истёк. |
| `credential_already_registered` | `passkey/register`, `passkeys/add/finish` | `credential_id` уже есть в БД. |
| `passkey_not_found` | `passkey/login`, `stepup/finish` | После проверки assertion passkey не найден у пользователя. |
| `passkey_counter_regression` | `passkey/login`, `stepup/finish` | Device-bound counter не продвинулся; synced 0/0 допускается. |
| `invalid_id` | `sessions/{id}/revoke`, `passkeys/{id}/revoke` | ID не является UUID. |
| `cannot_remove_last_credential` | `passkeys/{id}/revoke` | Это последний passkey и нет неистёкших recovery-кодов. |
| `invalid_recovery_code` | `recover/verify-code` | Recovery-код не совпал/истёк/уже использован. Legacy NULL-expiry коды инвалидированы 0003. Challenge уже израсходован. |
| Текст serde | `passkey/register`, `passkey/login`, `passkeys/add/finish` | `credential` не разобрался как ожидаемый JSON. |
| Текст `webauthn-rs` | WebAuthn-ошибки | Ошибка проверки церемонии; `error = webauthn_error`. |

### 5.3. Ошибки вне `AppError`

`Json`-экстрактор Axum сам обрабатывает:

- отсутствующий/неверный `Content-Type` — 415;
- синтаксическую ошибку JSON — 400;
- несоответствие типов — 422.

Тело таких ответов — не `{"error":...}`, а стандартный текстовый ответ Axum. Клиент
должен уметь обрабатывать оба формата.

`check_origin` возвращает 403 `forbidden`: в production missing `Origin` тоже 403, в dev
missing разрешён. Rate limit — 429, `require_stepup` — 403 `stepup_required`. Hard account
lockout удалён. 401 не содержит `WWW-Authenticate`. `healthz` при ошибке БД возвращает
503 с отдельным JSON (`ok:false`, `error:"database_unavailable"`), а не `AppError`.

## 6. Безопасность: решения и компромиссы

### 6.1. Реализованные решения

| Решение | Причина | Компромисс |
|---|---|---|
| Нет паролей | Нечего красть и подбирать; нет reset-flow. | Восстановление целиком зависит от passkey/recovery/email. |
| OTP — HMAC-SHA-256 с контекстом (user/purpose/id/expiry), 6 цифр, TTL 10 мин, 5 попыток | Код нельзя восстановить/переиспользовать в другом контексте; попытки ограничены. | 6 цифр — ~20 бит; защита держится на лимитах и TTL. |
| Brute-force controls | 5 попыток на OTP + per-email/IP rate limits; `failed_attempts` только для алертов. | Hard account lockout отсутствует; CAPTCHA/edge limits для публичного signup не реализованы. |
| SMTP через `lettre` или outbox | Реальная доставка в production; outbox для dev. | Внешний провайдер не проверялся; `opportunistic` только dev без credentials; SMTP-сбой `start` даёт 500, `recover/start` — generic. |
| Проверяется только последний OTP | Старые коды не работают после выдачи нового. | Старые строки остаются в БД; сортировка `created_at DESC, rowid DESC`. |
| Session-токен 256 бит, в БД SHA-256-хеш | Утечка БД не даёт готовые cookie. | Хеш без соли; токен высокоэнтропийный. |
| Абсолютный TTL 7 дней + idle 24 часа | Ограничивает украденную cookie. | `last_seen_at` обновляется на каждом запросе; cookie не ротируется. |
| HttpOnly + SameSite=Strict + Secure; production `__Host-al_session` | Снижает XSS/CSRF и защищает имя cookie. | Non-dev требует HTTPS и `__Host-`; `al_session` остаётся только вне production. |
| Привязка passkey-сессий к `passkey_id` | Удаление passkey отзывает его сессии. | Legacy-сессии с NULL `passkey_id` отозваны в 0003. |
| Step-up WebAuthn + `al_ceremony` | Свежая проверка владения passkey и привязка ceremony. | Окно 5 минут; ручные клиенты должны сохранять `al_ceremony`. |
| Проверка `Origin` на POST | Дополнительный барьер к SameSite. | В production missing Origin — 403; в dev разрешён. CSRF-токена нет. |
| WebAuthn через `webauthn-rs` | Origin-bound, phishing-resistant, приватный ключ не уходит. | `RP_ID` в production должен совпадать с `APP_URL` host, иначе нужен `ALLOW_RP_ID_PARENT`; HTTPS обязателен. |
| Passkey counter | `counter` колонка и regression policy. | Synced 0/0 допускается; device-bound regression — 400/audit. |
| Recovery-коды 72 бита, HMAC, TTL 365 дней, одноразовые | Достаточная энтропия; в БД только хеши; счётчики фильтруют expiry. | Одна попытка на challenge + rate limits; legacy NULL-expiry инвалидированы 0003. |
| Recovery отзывает все сессии/passkeys | Компрометация не оставляет старый доступ. | Пользователь обязан зарегистрировать новый passkey. |
| Rate limits + trusted proxy | Сдерживает подбор и не доверяет XFF от кого угодно. | In-memory/per-process; неправильные `TRUSTED_PROXY_CIDRS` ломают IP. |
| Транзакции OTP+outbox, recovery batch, passkey+session+recovery, recovery-revoke | Убирают часть частичных состояний. | Не все сценарии транзакционны; audit — best-effort. |
| `Cache-Control: no-store` на всех ответах | Запрещает кеширование чувствительных ответов. | Не заменяет CSP/security headers. |
| Admin server-side sessions (`admin_sessions`) | Opaque token hash, 1 час, logout revokes; old HMAC cookies invalid. | Общий `ADMIN_TOKEN`, нет ролей/2FA/отдельных admin-аккаунтов. |
| Cleanup expired rows | OTP/sessions/recovery/admin_sessions/outbox ограничены по TTL. | `audit_events` не чистятся. |
| Аудит основных событий | Есть след действий. | Best-effort: ошибки вставки логируются; не все неудачи пишутся. |

### 6.2. Что остаётся за периметром

- **Кража cookie.** Сессия — bearer. Passkey-binding и step-up уменьшают последствия,
  но украденная cookie работает до `expires_at`, idle timeout или отзыва. DPoP/DBSC
  не реализованы.
- **XSS.** HttpOnly не даёт украсть токен, но XSS может выполнять запросы от имени
  пользователя, включая step-up и удаление passkey.
- **Компрометация email на этапе регистрации.** Атакующий может зарегистрироваться
  первым и создать passkey. Recovery-политика ограничена recovery-кодами.
- **Malware на устройстве.** Может действовать в рамках сессии и использовать passkey.
- **Утечка файла SQLite.** Email, IP, User-Agent, audit metadata лежат в открытом виде.
  `outbox.body` содержит OTP только в dev+outbox и чистится через 1 день; при SMTP —
  redacted. Хеши OTP/recovery/session не дают прямого доступа.
- **SMTP.** Локальный Mailpit E2E прошёл; внешний провайдер не проверялся;
  retry/bounce-обработки нет. Сбой `start` после коммита OTP даёт 500; `recover/start`
  логирует сбой и отвечает generic. `SMTP_TLS=opportunistic` разрешён только dev без
  credentials; `none` только dev.
- **DoS/brute force.** Rate limits остаются in-memory/per-process; hard account lockout
  удалён, `failed_attempts` advisory. CAPTCHA/edge limits для публичного signup не
  реализованы. Challenge maps ограничены 10k; БД чистится по TTL, кроме audit.
- **Browser E2E.** 18/18 с virtual authenticator (visible step-up, SameSite=Strict,
  `al_ceremony`); real-device/browser matrix не проверялась.
- **Supply chain.** Зависимости не проверены аудитом.

### 6.3. Явные слабые места кода

- `X-Forwarded-For`/`X-Real-IP` используются только если peer входит в
  `TRUSTED_PROXY_CIDRS` при `TRUST_PROXY=true`; иначе берётся peer IP. Неправильные
  CIDR, CDN перед Caddy или прямой доступ могут сломать/подделать IP в аудите и лимитах.
- Admin — общий `ADMIN_TOKEN`, а не отдельные аккаунты: серверная `admin_sessions`
  запись (opaque token hash) и cookie `al_admin` живут 1 час, logout отзывает; нет
  ролей/2FA, смена `ADMIN_TOKEN` не инвалидирует уже созданные admin-сессии (их надо
  отзывать logout/cleanup). Login rate-limited 5/60 IP.
- `start` различает passkey-flow и code-flow, поэтому наличие passkey всё ещё можно
  определить. `verify-code`/`recover` для неизвестного пользователя отдают generic
  `invalid_code`.
- Транзакции покрывают OTP+outbox, batch recovery-кодов, passkey+session+recovery,
  recovery-revoke и удаление passkey, но проверка дубликата credential перед INSERT и
  связка «recovery-код + in-memory challenge» остаются нетранзакционными; audit —
  best-effort.
- Challenge maps и rate limiter in-memory: чистятся раз в 300 секунд/ограничены 10k, но
  не общие между инстансами; рестарт прерывает церемонии.
- Приложение само не ставит security headers и CORS; `deploy/Caddyfile` добавляет HSTS,
  CSP, `X-Content-Type-Options`, `Referrer-Policy` и `X-Frame-Options` на уровне Caddy.
  `Cache-Control: no-store` ставится приложением.
- SQLite: WAL, foreign keys и busy timeout 5s включены, но пул ограничен 5 соединениями;
  multi-writer/multi-instance не поддерживаются.
- `me.recovery_codes_remaining` и проверка последнего credential считают только
  неиспользованные неистёкшие recovery-коды. Legacy NULL-expiry коды инвалидированы
  0003 (`expires_at=1970...`) и не должны разрешать удаление последнего credential;
  новые коды всегда имеют `expires_at` и контекстный `recovery:v1` hash.
- `SMTP_TLS=none` разрешён только в dev; `opportunistic` — только dev без credentials.
- `recover/start` намеренно скрывает ошибку `create_otp` (доставка или БД) и отвечает
  generic-ответом; клиент не узнает, что код не отправлен/не создан.
- `healthz` проверяет БД, но graceful shutdown и отдельного readiness/liveness-контракта
  нет. Cleanup чистит OTP/sessions/recovery/admin_sessions/outbox, но не `audit_events`.
- Hard account lockout отсутствует: `failed_attempts` только для алертов; CAPTCHA/edge
  limits для публичного signup не реализованы.

### 6.4. Security review round 3

Текущий отчёт: [`../SECURITY_REVIEW_ROUND3.md`](../SECURITY_REVIEW_ROUND3.md).
`SECURITY_REVIEW.md` и `SECURITY_REVIEW_ROUND2.md` — исторические снимки, не текущий verdict.

**Unrestricted public v0.1 — NO-GO.** **Conditional GO** для fresh single-instance за
Caddy: `DEV_MODE=false`, HTTPS/`__Host-al_session`, `SMTP_TLS=required`, точный `RP_ID`,
strong secrets, admin disabled/network-restricted, 0003 после backup, edge CAPTCHA/rate
limits для signup/email abuse. Upgrade: 0003 + backup + counter backfill или
перерегистрация passkeys.

| Риск | Статус |
|---|---|
| R3-1 open signup / OTP/email abuse | blocker для unrestricted public; нужны CAPTCHA/edge limits |
| R3-5 recovery без delay/step-up | design residual для широкого public |
| Bearer sessions без DPoP/DBSC | residual; stolen cookie до TTL/revoke |
| R3-3 ADMIN_TOKEN rotation | не отзывает существующие `admin_sessions`; logout/1h TTL |
| R3-2 counter=0 у legacy passkeys | clone detection ослаблен на одну assertion до backfill/перерегистрации |
| R3-4 admin/ceremony cookie prefixes | `al_admin`/`al_ceremony` без `__Host-`/`__Secure-` |
| R2-10 start enumeration | `start` различает passkey-аккаунт |
| R2-13 OTP before SMTP | delivery failure оставляет валидный OTP + 500 |

## 7. Как расширять

### 7.1. Email delivery / SMTP

Уже реализовано:

- `EmailSender` в `src/email.rs`: `Outbox` или `Smtp` через `lettre` 0.11.
- `EMAIL_PROVIDER`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
  `SMTP_FROM`, `SMTP_TLS`; SMTP-поля валидируются на старте. `SMTP_TLS=required` в
  production; `opportunistic` только dev без credentials; `none` только dev.
- `create_otp` пишет OTP+outbox в одной транзакции, коммитит и затем отправляет письмо;
  таймаут отправки — 10 секунд. SMTP-пароль хранится как `SecretString` и не логируется.
- `outbox` пишется в обоих режимах; при SMTP body redacted, при dev+outbox — с кодом.
  Записи старше 1 дня удаляются.
- Локальный SMTP E2E через Mailpit прошёл; внешний провайдер не тестировался.

Что остаётся сделать для production:

1. Проверить доставку через реальный провайдер (SES/Postmark/корпоративный SMTP),
   включая SPF/DKIM/DMARC и попадание не в spam.
2. Добавить retry/queue: `status`, `attempts`, `next_attempt_at`, background worker и
   идемпотентность. Сейчас SMTP-сбой после коммита в `start` возвращает 500 без повтора,
   а `recover/start` скрывает ошибку и отвечает generic.
3. Обрабатывать bounce/complaint и не отправлять на invalid-адреса бесконечно.
4. Добавить шаблоны писем и локализацию (сейчас письмо — одна строка с кодом).
5. Добавить outbound rate limit и защиту от email bombing на уровне провайдера.
6. При необходимости добавить другие провайдеры через enum/trait, не ломая `EmailSender`.

### 7.2. Postgres

Текущий код жёстко использует `SqlitePool` и `?`-плейсхолдеры.

Шаги:

1. Включить feature `postgres` у `sqlx`, добавить `PgPool`.
2. Ввести абстракцию пула или отдельную сборку под Postgres; `sqlx::Any` возможен,
   но требует аккуратной работы с типами.
3. Переписать плейсхолдеры `?` → `$1`, `$2`, ...
4. Перенести схему: `UUID`, `TIMESTAMPTZ`, `JSONB`, `BIGSERIAL`/identity вместо
   `INTEGER PRIMARY KEY AUTOINCREMENT`, `TEXT` для email или `CITEXT`.
5. Разделить миграции по backend'ам; `sqlx::migrate!` должен указывать на нужный каталог.
6. Перенести существующие транзакции (OTP+outbox, passkey+session+recovery,
   recovery batch) и добавить недостающие для Postgres-модели.
7. Добавить индексы под запросы (сессии по `token_hash`, аудит по времени).
8. Проверить `ON DELETE CASCADE` и конкурентные `ensure_user`/`verify_otp`.
9. Прогнать интеграционные тесты на обоих backend'ах.

`?mode=rwc` — SQLite-специфика; для Postgres URL другой.

### 7.3. DPoP/DBSC и привязка сессии

Текущая cookie — bearer. Для proof-of-possession:

1. Добавить в `sessions` поля `binding_type` (`none`, `dpop`, `dbsc`) и `binding_jkt`
   (JWK thumbprint).
2. При login клиент присылает публичный ключ; сервер привязывает сессию к thumbprint.
3. На каждый API-запрос требовать `DPoP`-proof: проверить подпись, `htm`, `htu`,
   `iat`, `jti`, `ath`; хранить `jti` в коротком replay-кэше.
4. Для браузера использовать DBSC, где поддерживается, иначе — WebAuthn step-up
   на чувствительные действия.
5. Не считать короткий TTL заменой привязке: украденная cookie всё равно работает
   до истечения.
6. Это ломает текущий API-контракт; лучше делать в новой версии API.

### 7.4. Multi-tenancy

1. Добавить `tenants(id, slug, name, rp_id, app_url, ...)`.
2. Добавить `tenant_id` в `users`, `passkeys`, `sessions`, `otp_codes`,
   `recovery_codes`, `audit_events`; unique-ограничение `(tenant_id, email)`.
3. Резолвить tenant по `Host`/subdomain или пути; для каждого tenant — свой
   `Webauthn` (свой RP ID/origin).
4. Изолировать admin и аудит по tenant.
5. Не переиспользовать один `OTP_SECRET` между tenant'ами без необходимости; лучше
   derived per-tenant secret.
6. Продумать миграцию существующих данных и индексы.

Это существенное изменение схемы, не для v0.1.

### 7.5. Admin-действия

Сейчас admin только читает. Для действий:

1. Admin login уже есть (`/admin/login`, server-side `admin_sessions`, TTL 1 час);
   добавить роли, отдельные admin-аккаунты и 2FA вместо общего `ADMIN_TOKEN`.
2. Endpoint'ы: блокировка пользователя, отзыв всех сессий, отзыв passkey, удаление
   аккаунта, просмотр/экспорт аудита.
3. Проверять CSRF/Origin, писать аудит на каждое действие, требовать re-auth для
   опасных операций.
4. Не возвращать секреты (recovery-коды, токены) в admin-ответах.

## 8. Известные пробелы и hardening checklist

По состоянию на 2026-11-23. Порядок — приоритет, а не оценка сроков.

Ни реальная SMTP-доставка через внешний провайдер, ни real-device/browser matrix в этом
документе не проверялись. Browser E2E по `PROJECT_STATE.md` — 18/18 с Chrome CDP virtual
authenticator (visible step-up, SameSite=Strict, `al_ceremony`). `scripts/smoke.mjs` — HTTP
smoke-проверка health, OTP/outbox, admin login/logout и части endpoint'ов; он не покрывает
WebAuthn, authenticated dashboard, recovery, step-up и SMTP. Прогон: 26/26 с `ADMIN_TOKEN`;
без него — 21 passed, 5 skipped. Наличие smoke/E2E не заменяет unit/integration-тесты.

### P0 — до любого публичного развёртывания

- [ ] Добавить unit/integration-тесты (`cargo test` сейчас 0 тестов): OTP
      expiry/attempts/advisory-failures, session expiry/idle/revoke, recovery
      one-time/atomic/revoke and expired-count filtering, rate limits, revoke 404,
      health 503, SMTP success/failure, outbox redaction, add-passkey/step-up/ceremony
      binding, admin sessions/login/logout, cleanup of expired rows.
- [ ] Проверить SMTP на реальном провайдере (SES/Postmark/корпоративный SMTP), включая
      SPF/DKIM/DMARC и доставку не в spam.
- [ ] Browser E2E: 18/18 с virtual authenticator уже пройден (visible step-up,
      SameSite=Strict, `al_ceremony`); добавить CI и real-device/browser matrix.
- [ ] Общий challenge/rate-limit store для нескольких инстансов (очистка/лимиты уже есть).
- [ ] CSRF: production `Origin` уже обязателен; решить, нужен ли CSRF-токен для
      нестандартных клиентов, и покрыть missing-Origin тестами.
- [ ] Проверить `TRUST_PROXY`/`TRUSTED_PROXY_CIDRS` для реальной топологии (Caddy,
      CDN/load balancer); иначе IP в аудите/лимитах будет неверным.
- [ ] Security headers: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`,
      `X-Frame-Options`/`frame-ancestors`; `Cache-Control: no-store` уже есть.
- [ ] Cookie: `__Host-`/`Secure`/HTTPS-инварианты уже проверяются на старте; покрыть
      тестами и проверить reverse-proxy.
- [ ] Admin: роли, отдельные аккаунты и 2FA поверх серверных `admin_sessions`;
      сейчас это общий `ADMIN_TOKEN`, а его ротация не отзывает существующие admin-сессии.
- [ ] Аудит неудачных попыток и admin-доступа; не игнорировать ошибки записи аудита.
- [ ] Session rotation при login/повышении привилегий; idle timeout и revoke-all уже есть.
- [ ] Убрать/уменьшить user enumeration: `start` всё ещё различает passkey-flow (R2-10).
- [ ] SQLite: backup/restore drill, права на файл, retention для audit; cleanup для
      OTP/sessions/recovery/admin_sessions/outbox уже есть, WAL/busy timeout/foreign keys включены.
- [ ] Явная WebAuthn-политика (user verification, attestation), `ALLOW_RP_ID_PARENT`
      policy и проверка HTTPS/RP ID на старте; документация для reverse proxy.
- [ ] Step-up: покрыть тестами (5-минутное окно, отказ future-dated legacy) и UI.
- [ ] SMTP: retry/queue/delivery-status/bounce и защита от email bombing; сейчас OTP
      коммитится до send, delivery failure оставляет валидный код и 500 (R2-13).
- [ ] CAPTCHA/edge rate limits для публичного signup: hard account lockout удалён,
      `failed_attempts` только advisory (R3-1).
- [ ] Recovery hardening: delay/existing-passkey confirmation/step-up перед отзывом
      всех credentials (R3-5).

### P1 — следующий этап

- [ ] Postgres и multi-instance модель.
- [ ] DPoP/DBSC и привязка cookie/сессии к устройству (passkey-bound sessions уже есть).
- [ ] Counter backfill для legacy passkeys или перерегистрация; сейчас `counter=0`
      ослабляет clone detection на одну assertion (R3-2).
- [ ] `__Host-`/`__Secure-` префиксы для `al_admin`/`al_ceremony` (R3-4).
- [ ] Admin-действия: блокировка, отзыв сессий/passkeys, удаление.
- [ ] Смена email, удаление аккаунта, политика recovery.
- [ ] Полировка frontend: локализация (сейчас UI на английском), accessibility,
      browser matrix; add-passkey/step-up UI уже реализованы.
- [ ] Шаблоны писем, локализация, провайдерская retry/bounce-логика.
- [ ] Метрики, structured logs, readiness/liveness и graceful shutdown.
- [ ] CORS, если появится внешний SPA; сейчас только same-origin.
- [ ] Ограничение размера тела запроса и количества passkeys/сессий на пользователя.
- [ ] Проверить Docker Compose/Caddy/systemd end-to-end: image уже собран (13.7 MB
      binary, container healthy), остаются restore drill, non-root volume и healthcheck.

### P2 — позже

- [ ] Multi-tenancy.
- [ ] OIDC/SDK для внешних приложений.
- [ ] SSO/SCIM, risk signals (только как сигнал, не как замена криптографии).
- [ ] Экспорт аудита, retention policy, immutable storage.
- [ ] Pen-test и публичный security review.

## 9. Ручная проверка

HTTP-часть без WebAuthn:

```bash
# health + заголовки (ожидается 200 и Cache-Control: no-store)
curl -i -s http://localhost:8080/healthz

# начало входа (создаст пользователя, OTP и запись в outbox)
curl -s -X POST http://localhost:8080/api/auth/start \
  -H "content-type: application/json" \
  -d '{"email":"dev@example.com"}'

# код из dev outbox (работает при DEV_MODE=true)
curl -s http://localhost:8080/api/dev/outbox

# без сессии
curl -i -s http://localhost:8080/api/sessions
curl -s http://localhost:8080/api/me

# admin: без cookie — redirect на /admin/login; форма входа
curl -i -s "http://localhost:8080/admin"
curl -i -s "http://localhost:8080/admin/login"

# admin login с токеном (form); при успехе Set-Cookie al_admin
curl -i -s -X POST "http://localhost:8080/admin/login" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ADMIN_TOKEN"
```

SMTP можно проверить отдельно: локальный Mailpit E2E уже проходил; для внешнего задайте
`EMAIL_PROVIDER=smtp`, реальные `SMTP_*` и запросите код. Сбой доставки удобно имитировать
неверным `SMTP_HOST`: `start` вернёт 500 после коммита OTP; `recover/start` логирует сбой
и отвечает generic `flow: code`. В этом документе успешная внешняя SMTP-доставка не
фиксируется.

WebAuthn-регистрацию, вход, добавление passkey и step-up нужно проверять в браузере:
`curl` не создаст passkey. Для ручного API-клиента сохраняйте cookie jar: `al_session`
и `al_ceremony`; в production state-changing запросы обязаны отправлять `Origin`.
Откройте `http://localhost:8080`, введите email, возьмите код из `/dev/outbox`
(при dev+outbox), затем завершите WebAuthn-диалог.

Проверьте вручную:

- неверный OTP отклоняется, счётчик 5 попыток работает;
- после 5 неверных попыток код блокируется; hard account lockout нет, `failed_attempts`
  только для алертов;
- повторное использование кода отклоняется;
- в production cookie `__Host-al_session` имеет `HttpOnly`, `SameSite=Strict`, `Secure`;
  в dev/HTTP — `al_session`; `al_ceremony` HttpOnly/Strict;
- `GET /api/sessions` показывает текущую сессию; idle timeout 24 часа;
- revoke текущей сессии очищает cookie; revoke-all требует step-up и очищает cookie;
- повторный вход по passkey создаёт новую сессию, привязанную к passkey; counter
  regression отклоняется;
- добавление passkey требует step-up и `al_ceremony`, не меняет cookie и не выдаёт
  recovery-коды;
- удаление passkey требует step-up и отзывает сессии, привязанные к нему;
- recovery-код срабатывает один раз; успешный recovery отзывает все сессии и удаляет
  все passkeys; legacy NULL-expiry коды после 0003 не работают;
- revoke неизвестного/чужого session/passkey ID возвращает 404;
- при `EMAIL_PROVIDER=smtp` письмо отправляется, а `/dev/outbox` при `DEV_MODE=true`
  содержит redacted-запись без кода;
- при SMTP-сбое `start` возвращает 500, `recover/start` — generic-ответ;
- `DEV_MODE=false` скрывает outbox и требует SMTP (или allow-флаг для outbox);
- `Cache-Control: no-store` присутствует на API/health-ответах;
- `ADMIN_TOKEN` не задан — `/admin` даёт 404; задан — `/admin` редиректит на
  `/admin/login`, неверный токен даёт 403, верный создаёт `admin_sessions` и cookie;
  logout отзывает admin-сессию.

## 10. Ссылки

- [`../README.md`](../README.md) — quickstart, env, API summary.
- [`../deploy/README.md`](../deploy/README.md) — Docker Compose, Caddy, systemd, backup.
- [`../scripts/README.md`](../scripts/README.md) — HTTP smoke test.
- [`../SECURITY_REVIEW_ROUND3.md`](../SECURITY_REVIEW_ROUND3.md) — текущий round-3 review
  (NO-GO/conditional GO, R3-1…R3-5, R2 residuals).
- [`../SECURITY_REVIEW.md`](../SECURITY_REVIEW.md) — исторический review, не текущий verdict.
- [`../../PROJECT_STATE.md`](../../PROJECT_STATE.md) — состояние проекта и known gaps.
- [`../../docs/PRODUCT.md`](../../docs/PRODUCT.md) — продуктовое видение.
- [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) — целевая архитектура
  (не всё реализовано в v0.1).
