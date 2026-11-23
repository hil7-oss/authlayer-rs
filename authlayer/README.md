# AuthLayer

Self-hosted passwordless-аутентификация: вход по email-коду и passkeys. Пароли не запрашиваются и не хранятся.

> **Статус: v0.1, pre-release.** По `../PROJECT_STATE.md`: `cargo check`/`build`/`fmt`
> проходят, `cargo test` — 0 тестов. Live HTTP smoke: **26/26 с `ADMIN_TOKEN`**;
> без него — 21 passed, 5 skipped. Docker image собран: бинарник **13.7 MB**, read-only
> container healthy; локальный SMTP E2E через Mailpit прошёл, внешний провайдер не
> тестировался. Browser E2E: **18/18** с Chrome CDP virtual authenticator (visible step-up,
> SameSite=Strict, `al_ceremony`); реальные устройства/другие браузеры и внешний SMTP
> не проверялись. Unrestricted public v0.1 — **NO-GO**; conditional GO — только fresh
> single-instance за Caddy по условиям round-3 review
> ([`SECURITY_REVIEW_ROUND3.md`](SECURITY_REVIEW_ROUND3.md)); `SECURITY_REVIEW.md` и
> round 2 — исторические. Внутренние review не заменяют внешний аудит. Не использовать
> в production без выполнения conditional-GO условий.

| Параметр | Значение |
|---|---|
| Версия | `0.1.0` (`Cargo.toml`) |
| Хранилище | SQLite, внешняя БД не нужна |
| Поставка | один Rust-бинарник; `static/` встроен в него при компиляции |
| Email | `EMAIL_PROVIDER=outbox` (dev) или `smtp` через `lettre`; внешний SMTP-провайдер не тестировался |
| Сессия | 7 дней абсолютный TTL + 24 часа idle; cookie `SameSite=Strict`, `__Host-al_session` в production |
| Лицензия | Apache-2.0; файл `../LICENSE` в корне репозитория |

## Обновление с предыдущей сборки

`migrations/0003_legacy_and_cookie.sql` меняет поведение:

- legacy recovery-коды с `NULL expires_at` инвалидируются; после входа нужно
  сгенерировать новые recovery-коды;
- legacy-сессии с `NULL passkey_id` отзываются — все такие пользователи должны
  перелогиниться;
- старые HMAC admin-cookie недействительны — нужен новый `/admin/login`;
- добавляются `passkeys.counter` и серверная таблица `admin_sessions`.

Обновление без потери passkeys возможно, но активные сессии и старые recovery-коды
намеренно ломаются. Перед 0003 сделайте backup. Существующие passkeys получают
`counter=0`: до counter backfill или перерегистрации passkey clone detection ослаблен
на одну assertion (R3-2).

## Что уже есть

- Email OTP: 6 цифр, HMAC-SHA-256 с контекстом (user/purpose/id/expiry), TTL 10 минут по умолчанию, максимум 5 попыток, одноразовый.
- Email delivery: `EMAIL_PROVIDER=outbox` для разработки или `smtp` через `lettre`; SMTP-конфиг валидируется на старте, пароли не логируются.
- WebAuthn/passkeys через `webauthn-rs` 0.6: регистрация, вход и добавление passkey к текущей сессии (через step-up); `passkeys.counter` проверяется на regression, synced 0/0 допускается с audit.
- Серверные сессии: случайный токен, SHA-256-хеш в БД, HttpOnly-cookie, `SameSite=Strict`; абсолютный TTL 7 дней и idle timeout 24 часа.
- Production-cookie: `__Host-al_session`, `Secure`; имя `al_session` используется только вне production (dev).
- Recovery-коды: 8 одноразовых кодов, TTL 365 дней по умолчанию, показываются один раз; успешный recovery отзывает все сессии и passkeys. Legacy NULL-expiry коды инвалидируются в 0003.
- Browser UI (vanilla JS, `static/app.js`): email → OTP → passkey, вход по passkey,
  recovery, dashboard, add/revoke passkey, sessions, revoke-all, step-up re-auth, recovery-коды.
- Browser E2E: 18/18 с Chrome CDP virtual authenticator (visible step-up, SameSite=Strict,
  `al_ceremony`); реальные устройства/другие браузеры не проверялись.
- SQLite + миграции, автоматически применяются при старте; WAL, foreign keys и busy timeout 5s.
- Outbox: при `outbox` письма не отправляются; при `smtp` отправляются, но копия письма
  всё равно пишется в БД с redacted body. `/dev/outbox` доступен при `DEV_MODE=true`.
- Read-only admin: `/admin/login`; серверные `admin_sessions` (opaque token hash, 1 час, logout отзывает).
- Аудит основных событий в `audit_events`, включая admin login/view и recovery.
- Brute-force controls: 5 попыток на OTP + per-email/IP rate limits; `failed_attempts` — advisory для алертов, hard lockout нет. Для публичного signup рекомендуются CAPTCHA/edge limits.
- Cleanup: OTP, sessions, recovery-коды, admin sessions и outbox старше 1 дня чистятся при старте и раз в 5 минут; audit не чистится.
- Healthcheck `/healthz` с проверкой БД: 200 или 503.
- `Cache-Control: no-store` на всех ответах.
- Rate limits на auth-endpoint'ы (in-memory, per-process, с периодической очисткой).
- Docker image: 13.7 MB binary, read-only container healthy; Docker Compose + Caddy и systemd unit в `deploy/`.

## Чего ещё нет

- Проверки SMTP на реальном внешнем провайдере: реализация и конфиг есть, но фактическая
  доставка через SES/Postmark/корпоративный SMTP в этом репозитории не подтверждена.
- Postgres: только SQLite.
- DPoP/DBSC и криптографической привязки cookie к устройству: сессия — bearer-токен,
  хотя passkey-сессии хранят `passkey_id` и отзываются при удалении passkey.
- Unit/integration-тестов и CI. По `PROJECT_STATE.md` `cargo test` проходит с 0 тестами;
  browser E2E — 18/18 с virtual authenticator, но real-device/browser matrix и CI нет.
  Внутренний security review есть, внешнего аудита нет.
- Admin-действий: страница только читает данные.
- CAPTCHA/edge rate limiting для публичного signup: hard account lockout не используется,
  защита — OTP attempts + in-memory rate limits.
- Удаления аккаунта, смены email, multi-tenancy.
- Локализации: UI и письма на английском; русского интерфейса нет.

## Быстрый старт (локально)

### Требования

- Rust stable. Проект использует edition 2024 (минимум 1.85); `deploy/README.md` рекомендует Rust 1.100+.
- Windows или Linux.
- Браузер с поддержкой WebAuthn/passkeys.
- Внешняя БД не нужна: SQLite создаётся файлом.
- Для сборки на Windows нужен MSVC toolchain (Visual Studio Build Tools с C++ workload).

### Запуск

Из корня репозитория:

```powershell
cd authlayer

$env:APP_URL="http://localhost:8080"
$env:RP_ID="localhost"
$env:DATABASE_URL="sqlite://authlayer.db?mode=rwc"
$env:DEV_MODE="true"
$env:OTP_SECRET="dev-otp-secret-0123456789abcdef0123456789abcdef"

cargo run
```

Linux/macOS:

```bash
cd authlayer

export APP_URL=http://localhost:8080
export RP_ID=localhost
export DATABASE_URL="sqlite://authlayer.db?mode=rwc"
export DEV_MODE=true
export OTP_SECRET=dev-otp-secret-0123456789abcdef0123456789abcdef

cargo run
```

Для локального запуска нужно явно задать env из блока выше: `DEV_MODE` по умолчанию
`false`, а без `OTP_SECRET` сервер не стартует вне dev-режима. В `DEV_MODE=true` сервер
требует loopback `BIND_ADDR`/`APP_URL`; для не-loopback dev-конфигурации нужен
`ALLOW_INSECURE_DEV_MODE=true` (только для изолированной разработки). `EMAIL_PROVIDER`
по умолчанию `outbox`, и в non-dev режиме outbox запрещён, если не задан
`ALLOW_OUTBOX_WITHOUT_DEV=true`.

### SMTP (опционально)

Для реальной отправки писем:

```dotenv
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-user
SMTP_PASSWORD=your-password
SMTP_FROM="AuthLayer <no-reply@example.com>"
SMTP_TLS=required
```

`SMTP_HOST` и `SMTP_FROM` обязательны при `EMAIL_PROVIDER=smtp`; `SMTP_USERNAME` и
`SMTP_PASSWORD` задаются вместе. При `SMTP_TLS=required` и порту `465` используется
implicit TLS, на остальных портах — STARTTLS. Пароль не пишется в логи.
`SMTP_TLS=none` разрешён только при `DEV_MODE=true` и отправляет credentials без TLS
с warning. `SMTP_TLS=opportunistic` разрешён только в dev **без** `SMTP_USERNAME`/
`SMTP_PASSWORD`; production должен использовать `SMTP_TLS=required`.
Локальный SMTP E2E через Mailpit прошёл; внешний провайдер не тестировался.

Поведение:

- `EMAIL_PROVIDER=outbox` (по умолчанию) — письма не отправляются, код виден в
  `/dev/outbox` при `DEV_MODE=true`. Вне dev outbox запрещён, если не задан
  `ALLOW_OUTBOX_WITHOUT_DEV=true`.
- `EMAIL_PROVIDER=smtp` — письмо отправляется. Запись в `outbox` всё равно создаётся,
  но её тело редактируется (`One-time code generated and sent by email.`), поэтому код
  не виден даже при `DEV_MODE=true`.
- При SMTP-сбое после коммита OTP `start` возвращает 500, и пользователь должен запросить
  новый код. `recover/start` в этом случае логирует `recovery_start_delivery_failed` и
  всё равно отвечает generic `flow: code`, чтобы не раскрывать наличие аккаунта.

### Что открыть

| URL | Что там |
|---|---|
| <http://localhost:8080> | UI: вход по email/passkey, recovery, dashboard |
| <http://localhost:8080/dev/outbox> | Последние 50 писем (retention 1 день); при `outbox` — код, при `smtp` — redacted-запись. Требует `DEV_MODE=true` |
| <http://localhost:8080/api/dev/outbox> | То же в JSON |
| <http://localhost:8080/healthz> | Healthcheck с проверкой БД: 200 или 503 |
| <http://localhost:8080/admin/login> | Вход в read-only admin, если задан `ADMIN_TOKEN` |

### Первый вход

UI реализован в `static/app.js` и работает в браузере с поддержкой WebAuthn/passkeys.

1. Откройте `http://localhost:8080`.
2. Введите email.
3. Возьмите 6-значный код: при `EMAIL_PROVIDER=outbox` — на `/dev/outbox`; при `smtp` —
   из письма (в `/dev/outbox` будет redacted-запись, не код).
4. Введите код. Сервер вернёт WebAuthn-опции регистрации passkey.
5. Создайте passkey (Face ID, Touch ID, Windows Hello, PIN).
6. Сохраните 8 recovery-кодов: они показываются только один раз.

### Важные локальные нюансы

- **WebAuthn требует secure context.** Браузеры считают `http://localhost` и `http://127.0.0.1`
  secure context, поэтому локально HTTPS не нужен. Для доступа по IP/LAN нужен HTTPS,
  а `RP_ID` должен совпадать с доменом.
- `RP_ID` — это домен без схемы, порта и пути: `localhost`, `auth.example.com`.
  В production `RP_ID` должен совпадать с host из `APP_URL`; parent/другой RP ID
  разрешается только явно через `ALLOW_RP_ID_PARENT=true`.
- `APP_URL` должен точно совпадать с origin, который видит браузер: схема, хост и порт.
  От этого зависит проверка `Origin` и WebAuthn. В production `APP_URL` обязан быть HTTPS.
- `COOKIE_SECURE=true` на plain HTTP приведёт к тому, что браузер не сохранит cookie.
  В production `COOKIE_SECURE=false` запрещён, `COOKIE_NAME` должен начинаться с `__Host-`
  (по умолчанию `__Host-al_session`); в dev/HTTP используется `al_session`.
- State-changing запросы в production обязаны присылать `Origin`; без него — 403.
  В `DEV_MODE` отсутствие `Origin` разрешено для локальных smoke/E2E.
- WebAuthn/recovery/add-passkey/step-up flow используют HttpOnly `SameSite=Strict`
  cookie `al_ceremony` (10 минут). Ручные API-клиенты должны сохранять её между
  start/options и finish/verify запросами.
- `BIND_ADDR` по умолчанию `127.0.0.1:8080`. Для Docker/LAN задайте `0.0.0.0:8080`
  осознанно и только за reverse proxy/TLS; при `DEV_MODE=true` non-loopback требует
  `ALLOW_INSECURE_DEV_MODE=true`.
- `DEV_MODE=false` отключает `/dev/outbox` и `/api/dev/outbox` (оба вернут 404).
- `static/index.html`, `static/app.js`, `static/style.css` встроены через `include_str!`.
  После их изменения нужен перезапуск `cargo run`/пересборка.

## Пользовательский поток

```text
Первый вход:
  email → OTP из письма → создание passkey → сессия
                                          └→ 8 recovery-кодов (один раз)

Следующий вход:
  email → passkey (Face ID / Touch ID / Windows Hello) → сессия

Потеря passkey:
  email → OTP → recovery-код → создание нового passkey → сессия
```

1. **Регистрация.** Пользователь вводит email. Если passkey ещё нет, сервер создаёт
   пользователя (если его не было), генерирует OTP, пишет outbox-запись и передаёт письмо
   выбранному провайдеру (`outbox` — no-op, SMTP — реальная отправка).
2. **Подтверждение email.** После верного кода сервер выдаёт WebAuthn-опции регистрации.
3. **Passkey.** Браузер создаёт passkey; сервер сохраняет публичную часть и выдаёт сессию.
   При первом passkey возвращаются 8 recovery-кодов.
4. **Следующий вход.** Для пользователя с passkey `/api/auth/start` сразу возвращает
   WebAuthn-опции входа, без email-кода.
5. **Восстановление.** Если passkey потерян, используется отдельный flow:
   email-код → recovery-код → отзыв всех сессий/passkeys → регистрация нового passkey.
6. **Сессия.** Абсолютный срок 7 дней (`SESSION_TTL_DAYS`), idle timeout 24 часа
   (`SESSION_IDLE_HOURS`), хранится на сервере и отзывается через logout,
   `/api/sessions/{id}/revoke` или `/api/sessions/revoke-all` (последний требует step-up).

### Ограничения текущего flow

- Email-код — **только bootstrap**. Если у пользователя уже есть passkey,
  `/api/auth/verify-code` вернёт `use_passkey`; входа по email-коду как fallback в v0.1 нет.
- Добавление passkey к текущей сессии доступно через
  `POST /api/passkeys/add/start` и `POST /api/passkeys/add/finish`; UI поддерживает
  этот flow через step-up. Новый passkey не создаёт новую сессию и не выдаёт recovery-коды.
- Recovery отзывает все старые сессии и удаляет все passkeys; после recovery обязательна
  регистрация нового passkey.
- Если у пользователя нет ни passkey, ни неиспользованных recovery-кодов, штатного
  self-service восстановления нет: admin-действий в v0.1 тоже нет.

## Модель безопасности

### Что реализовано

| Механизм | Реализация |
|---|---|
| Пароли | Не хранятся и не запрашиваются. В схеме БД нет колонки пароля, нет password reset. |
| Email OTP | 6 цифр, HMAC-SHA-256 с контекстом (user/purpose/otp_id/expiry), TTL 10 минут, 5 попыток, одноразовый. Доставка через `outbox` или SMTP. Проверяется только последний выданный код. |
| Brute-force controls | 5 попыток на OTP + per-email/IP rate limits; `failed_attempts` — advisory для алертов, hard lockout нет. CAPTCHA/edge limits рекомендуются для публичного signup. |
| Email delivery | `lettre` SMTP или outbox; SMTP TLS `required` в production, `opportunistic` только dev без credentials, `none` только dev; таймаут 10 секунд; пароль не логируется. При SMTP тело outbox-записи редактируется. |
| Passkeys | `webauthn-rs` 0.6, проверка origin/RP ID, одноразовый challenge, `passkeys.counter` regression policy (synced 0/0 допускается с audit). Add/revoke требуют step-up. |
| Ceremony cookie | HttpOnly `SameSite=Strict` `al_ceremony` (10 минут) связывает challenge с клиентом; обязательна для WebAuthn/recovery/add/step-up finish. |
| Сессии | 32 случайных байта, в БД SHA-256-хеш, cookie `HttpOnly`/`SameSite=Strict`; абсолютный TTL 7 дней, idle timeout 24 часа, привязка к `passkey_id` для passkey-сессий. |
| Cookie names | Production: `__Host-al_session` + `Secure`; `al_session` — только вне production. Non-dev отклоняет `COOKIE_SECURE=false`, non-HTTPS `APP_URL` и non-`__Host-` имя. |
| Step-up | Повторный WebAuthn для добавления/удаления passkey, `recovery/regenerate` и `sessions/revoke-all`; окно 5 минут, хранится в `sessions.stepup_at`. |
| Отзыв | `revoked_at`; logout, revoke session/passkey, revoke-all; удаление passkey отзывает сессии, привязанные к нему; неизвестный/чужой ID — 404. |
| Recovery | 8 кодов по 9 случайных байт (72 бита), HMAC с контекстом, TTL 365 дней, одноразовые; счётчики/проверка последнего credential фильтруют expiry. Legacy `NULL expires_at` инвалидируются в 0003. Успешный recovery отзывает все сессии и удаляет все passkeys. |
| CSRF | Production требует `Origin` для state-changing запросов; в dev missing Origin разрешён; плюс `SameSite=Strict`. CSRF-токена нет. |
| Аудит | Основные события, admin login/view/logout, recovery и security notifications (best-effort). |
| Транзакции | OTP+outbox, batch recovery-кодов, passkey+session+recovery, recovery-revoke и удаление passkey коммитятся атомарно. |
| Cache | `Cache-Control: no-store` добавляется ко всем ответам. |
| Rate limit | In-memory, per-process: `start` 5/60 email + 30/60 IP; `verify-code` 10/60 email + 20/60 IP; `passkey/register`, `passkey/login`, `stepup/*`, `passkeys/add/*` 20/60 IP; `recover/start` 3/300 email + 20/300 IP; `recover/verify-email` 5/60 email + 10/60 IP; `recover/verify-code` 5/60 email + 10/60 IP; `admin/login` 5/60 IP. |
| Proxy IP | `X-Forwarded-For`/`X-Real-IP` учитываются только от `TRUSTED_PROXY_CIDRS` при `TRUST_PROXY=true`; иначе peer IP. |
| SQLite | WAL, foreign keys и busy timeout 5s; cleanup OTP/sessions/recovery/admin_sessions/outbox при старте и раз в 5 минут. |
| Outbox | Тело с OTP хранится только в dev+outbox; при SMTP — redacted. Записи старше 1 дня удаляются при старте и раз в 5 минут. |

### Честные ограничения

- **Cookie — bearer-токен.** Кто украл cookie, тот действует как пользователь до истечения
  срока или отзыва. DPoP/DBSC/device binding не реализованы.
- **In-memory challenges и rate limiter.** Рестарт процесса убивает незавершённые
  WebAuthn/recovery-церемонии; несколько инстансов без sticky sessions или общего store
  работать не будут.
- **SMTP внешний провайдер не проверен.** Локальный Mailpit E2E прошёл, но SES/Postmark/
  корпоративный SMTP не подтверждён. При сбое после коммита OTP `start` отдаёт 500;
  `recover/start` логирует сбой и отвечает generic-ответом.
- **Outbox:** plaintext OTP хранится только при `DEV_MODE=true` + `EMAIL_PROVIDER=outbox`;
  при SMTP тело редактируется. Записи старше 1 дня удаляются периодической очисткой.
- **Rate limits — in-memory и per-process.** Общего limiter для нескольких инстансов нет;
  list/revoke/regenerate не ограничены (admin login — ограничен).
- **`X-Forwarded-For`/`X-Real-IP` учитываются только при `TRUST_PROXY=true` и peer IP из
  `TRUSTED_PROXY_CIDRS`.** При неправильной настройке доверенных CIDR или CDN перед
  прокси возможна подделка IP; по умолчанию заголовки игнорируются.
- **Admin — общий `ADMIN_TOKEN`, а не отдельные аккаунты.** `/admin/login` создаёт
  серверную запись `admin_sessions` (opaque token hash, TTL 1 час, logout отзывает),
  cookie `al_admin` HttpOnly/Strict/Path=/admin. Ротация `ADMIN_TOKEN` не отзывает
  существующие admin-сессии (R3-3); нет ролей, 2FA и audit-разделения.
- **Hard account lockout отсутствует.** `failed_attempts` — advisory; защита — 5 попыток
  на OTP + per-email/IP rate limits. CAPTCHA/edge limits для публичного signup не
  реализованы.
- **Step-up действует 5 минут.** `stepup_at = now`; `require_stepup` принимает только
  `0 <= now - stepup_at <= 5 минут`, future-dated legacy отклоняются. После истечения
  нужен повторный WebAuthn.
- **Транзакции покрывают не все сценарии.** OTP+outbox, batch recovery-кодов,
  passkey+session+recovery, recovery-revoke и удаление passkey атомарны; проверка
  дубликата credential перед INSERT и связка «recovery-код + in-memory challenge»
  остаются нетранзакционными. Аудит — best-effort.
- **CSRF-токена нет:** в production обязателен `Origin` + `SameSite=Strict`; в dev
  missing `Origin` разрешён. Это не заменяет CSRF-токен для нестандартных клиентов.
- **Cookie names:** session cookie использует `__Host-` в production, но `al_admin`
  и `al_ceremony` пока без `__Host-`/`__Secure-` (R3-4).
- **SQLite:** один файл, максимум 5 соединений; WAL/busy timeout/foreign keys включены,
  но multi-writer нагрузки и multi-instance не поддерживаются.
- **Нет удаления аккаунта, смены email, блокировки пользователя, admin-действий.**
- **User enumeration уменьшен, но не устранён:** `verify-code`/`recover` для неизвестного
  пользователя отдают generic `invalid_code`, однако `start` различает passkey-flow и
  code-flow.
- **Browser E2E:** 18/18 с virtual authenticator (visible step-up, SameSite=Strict,
  `al_ceremony`); real-device/browser matrix не проверялась.
- **Нет unit/integration-тестов, CI и real-device browser matrix; внешнего security
  audit нет (внутренний review есть).** HTTP smoke, Mailpit SMTP и browser E2E с virtual
  authenticator проходят, но не заменяют тесты.

Подробный разбор решений и компромиссов — в [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

### Security review round 3

Полный отчёт: [`SECURITY_REVIEW_ROUND3.md`](SECURITY_REVIEW_ROUND3.md). Предыдущие
`SECURITY_REVIEW.md`/round-2 — исторические снимки, а не текущий verdict.

**Unrestricted public v0.1 — NO-GO.** **Conditional GO** только для fresh single-instance
за Caddy, если одновременно выполнены: `DEV_MODE=false`, HTTPS и
`__Host-al_session`, `SMTP_TLS=required`, точный `RP_ID`, сильные secrets, admin выключен
или ограничен сетью, миграция 0003 применена после backup, а на edge стоят CAPTCHA/rate
limits для signup/email abuse. Для upgrade: 0003 + backup и либо counter backfill, либо
перерегистрация passkeys.

| Риск | Статус |
|---|---|
| R3-1: open signup → OTP/email abuse без CAPTCHA/edge limits | главный blocker для unrestricted public |
| R3-5: recovery сразу отзывает все credentials по email OTP + recovery code, без delay/step-up | design residual для широкого public |
| Bearer sessions без DPoP/DBSC | residual; stolen cookie работает до TTL/revoke |
| R3-3: ротация `ADMIN_TOKEN` не отзывает существующие `admin_sessions` | logout/1h TTL; admin read-only/optional |
| R3-2: legacy passkeys получают `counter=0` после 0003 | clone detection ослаблен на одну assertion до backfill/перерегистрации |
| R3-4: `al_admin`/`al_ceremony` без `__Host-`/`__Secure-` | низкий; session cookie защищён `__Host-` |
| R2-10: `start` различает passkey-аккаунт | enumeration residual |
| R2-13: OTP коммитится до SMTP send | при delivery failure остаётся валидный код + 500 |

## API

Все JSON-эндпоинты отдают `Content-Type: application/json`. Ошибки — в формате
`{"error":"...","message":"..."}`.

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| `GET` | `/` | — | HTML UI |
| `GET` | `/app.js` | — | JS UI (vanilla JS, WebAuthn) |
| `GET` | `/style.css` | — | CSS UI |
| `GET` | `/healthz` | — | Healthcheck: проверяет БД; 200 или 503 с `ok:false`/`database_unavailable` |
| `POST` | `/api/auth/start` | — | Начать вход: вернуть passkey-опции или отправить email-код |
| `POST` | `/api/auth/verify-code` | — | Проверить email-код; вернуть опции регистрации passkey |
| `POST` | `/api/auth/passkey/register` | `challenge_id` | Завершить регистрацию passkey; выдать сессию и recovery-коды при первом passkey |
| `POST` | `/api/auth/passkey/login` | `challenge_id` | Завершить вход по passkey; выдать сессию, привязанную к passkey |
| `POST` | `/api/auth/stepup/start` | cookie | Начать step-up: вернуть WebAuthn-опции |
| `POST` | `/api/auth/stepup/finish` | cookie + challenge | Завершить step-up; `stepup_at` действует ограниченное время |
| `POST` | `/api/auth/logout` | cookie (опционально) | Отозвать текущую сессию и очистить cookie |
| `GET` | `/api/me` | cookie (опционально) | Профиль и счётчики; без сессии — `{"authenticated":false}` |
| `GET` | `/api/sessions` | cookie | Активные сессии пользователя |
| `POST` | `/api/sessions/revoke-all` | cookie + step-up | Отозвать все сессии пользователя и очистить cookie |
| `POST` | `/api/sessions/{id}/revoke` | cookie | Отозвать сессию по ID; неизвестный/чужой ID — 404 |
| `GET` | `/api/passkeys` | cookie | Список passkeys пользователя |
| `POST` | `/api/passkeys/add/start` | cookie + step-up | Начать добавление passkey к текущей сессии |
| `POST` | `/api/passkeys/add/finish` | cookie + step-up | Завершить добавление passkey; новая сессия не создаётся |
| `POST` | `/api/passkeys/{id}/revoke` | cookie + step-up | Удалить passkey; отзывает сессии, привязанные к нему; неизвестный/чужой ID — 404 |
| `POST` | `/api/recovery/regenerate` | cookie + step-up | Удалить неиспользованные recovery-коды и выдать 8 новых |
| `POST` | `/api/auth/recover/start` | — | Начать восстановление: отправить email-код (generic-ответ) |
| `POST` | `/api/auth/recover/verify-email` | — | Проверить email-код восстановления |
| `POST` | `/api/auth/recover/verify-code` | — | Проверить recovery-код; отозвать сессии/passkeys и вернуть опции нового passkey |
| `GET` | `/dev/outbox` | `DEV_MODE` | HTML dev outbox, последние 50 писем |
| `GET` | `/api/dev/outbox` | `DEV_MODE` | JSON dev outbox |
| `GET` | `/admin/login` | `ADMIN_TOKEN` | Форма входа admin |
| `POST` | `/admin/login` | `ADMIN_TOKEN` | Принять `token` (form или JSON), выдать `al_admin` cookie |
| `POST` | `/admin/logout` | admin cookie | Очистить admin cookie |
| `GET` | `/admin` | admin cookie | Read-only admin; без cookie — redirect на `/admin/login` |

`challenge_id` — одноразовый идентификатор серверной WebAuthn/recovery-церемонии.
Для `passkey/register`, `passkey/login` и recovery-вызовов сессия не нужна. Для
`/api/passkeys/add/*` нужна действующая cookie и свежий step-up: challenge привязан к
текущему пользователю, живёт 2 минуты, одноразовый, новая сессия по завершении не
создаётся. Cookie-доступ означает, что нужна действующая сессия (кроме `logout` и `me`,
где она опциональна). Step-up — отдельная cookie-сессия + WebAuthn; он требуется для
add/revoke passkey, `recovery/regenerate` и `sessions/revoke-all`.

Все WebAuthn/recovery/add-passkey/step-up flow дополнительно привязываются к HttpOnly
`SameSite=Strict` cookie **`al_ceremony`** (10 минут): сервер выставляет её вместе с
`challenge_id` и проверяет при finish/verify. Ручные API-клиенты обязаны сохранять эту
cookie между запросами. Для state-changing запросов в production обязателен `Origin`;
в `DEV_MODE` запрос без `Origin` разрешён.

`/admin/login` создаёт серверную запись в `admin_sessions` (opaque token hash, 1 час,
logout отзывает) и выдаёт cookie `al_admin`.

### Тела запросов

```text
POST /api/auth/start                 {"email":"user@example.com"}
POST /api/auth/verify-code           {"email":"user@example.com","code":"123456"}
POST /api/auth/passkey/register      {"challenge_id":"...","credential":{...}}
POST /api/auth/passkey/login         {"challenge_id":"...","credential":{...}}
POST /api/auth/stepup/finish         {"challenge_id":"...","credential":{...}}
POST /api/passkeys/add/finish        {"challenge_id":"...","credential":{...}}
POST /api/auth/recover/start         {"email":"user@example.com"}
POST /api/auth/recover/verify-email  {"email":"user@example.com","code":"123456"}
POST /api/auth/recover/verify-code   {"challenge_id":"...","recovery_code":"ABCD-EFGH-IJKL"}
POST /admin/login                    token=<token>  (form) или {"token":"..."} (JSON)
```

`credential` — объект `PublicKeyCredential` из браузера, сериализованный в JSON в формате,
который ожидает `webauthn-rs` (ArrayBuffer → base64url). Для `navigator.credentials.create`
используется `options.publicKey` из ответа; для `navigator.credentials.get` — аналогично.

`POST /api/auth/logout`, `POST /api/sessions/{id}/revoke`, `POST /api/sessions/revoke-all`,
`POST /api/passkeys/{id}/revoke`, `POST /api/passkeys/add/start`,
`POST /api/auth/stepup/start` и `POST /api/recovery/regenerate` тела не требуют.

### Примеры ответов

```json
// POST /api/auth/start — у пользователя ещё нет passkey
{"flow":"code","email":"user@example.com","dev_outbox":"/dev/outbox"}

// POST /api/auth/start — у пользователя уже есть passkey
{"flow":"passkey","challenge_id":"...","options":{...}}

// POST /api/auth/verify-code
{"flow":"register_passkey","challenge_id":"...","options":{...}}

// POST /api/auth/passkey/register — при первом passkey
{"ok":true,"recovery_codes":["ABCD-EFGH-IJKL","..."]}

// POST /api/auth/passkey/login
{"ok":true}

// POST /api/auth/stepup/start
{"challenge_id":"...","options":{...}}

// POST /api/auth/stepup/finish
{"ok":true,"stepup_until":"..."}

// POST /api/passkeys/add/start
{"challenge_id":"...","options":{...}}

// POST /api/passkeys/add/finish
{"ok":true}

// POST /api/sessions/revoke-all
{"ok":true}

// GET /api/me — с сессией
{"authenticated":true,"user":{"id":"...","email":"user@example.com"},"passkeys":1,"sessions":1,"recovery_codes_remaining":8,"session_expires_at":"..."}
```

При `DEV_MODE=false` поле `dev_outbox` равно `null`.

### Ошибки

```json
{"error":"bad_request","message":"invalid_code"}
```

Для `400 bad_request` машинный код лежит в `message` (`invalid_code`, `use_passkey`,
`challenge_expired`, `challenge_not_found`, `passkey_counter_regression`, `no_passkeys`,
`registration_failed`, `invalid_request` и т.д.). Для остальных категорий `error` —
стабильный код: `unauthenticated`, `forbidden`, `not_found`, `too_many_requests`,
`stepup_required` (403), `webauthn_error`, `internal_error`. Полная таблица — в
[`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md#5-ошибки).

Неизвестный/неактивный пользователь в `verify-code`/`recover/verify-email` получает generic
`invalid_code`, чтобы уменьшить enumeration. `use_passkey` возвращается только после
проверки кода. Hard account lockout удалён: `failed_attempts` только для алертов; защита —
5 попыток на OTP и rate limits. `smtp`-сбой после коммита OTP в `start` даёт
`500 internal_error`; `recover/start` логирует сбой и отвечает generic-ответом.
Неизвестный/чужой ID в revoke-endpoint'ах — `404 not_found`. В production отсутствующий
`Origin` даёт `403 forbidden`; несовпадение `al_ceremony` — `400 challenge_not_found`.
Ошибки разбора JSON (неверный `Content-Type`, синтаксис, типы) обрабатываются Axum и могут
вернуть `400`/`415`/`422` с текстовым телом — это не формат `AppError`.

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8080` | Адрес и порт HTTP-сервера. Для Docker/LAN: `0.0.0.0:8080`. В `DEV_MODE=true` должен быть loopback. |
| `APP_URL` | `http://localhost:8080` | Публичный origin. В production обязан быть `https`; должен совпадать с браузерным origin. В `DEV_MODE=true` должен быть loopback. |
| `RP_ID` | host из `APP_URL` | WebAuthn Relying Party ID: домен без схемы/порта/пути. В production должен совпадать с host `APP_URL`; parent/другой RP ID — только при `ALLOW_RP_ID_PARENT=true`. |
| `RP_NAME` | `AuthLayer` | Отображаемое имя в WebAuthn-диалоге. |
| `ALLOW_RP_ID_PARENT` | `false` | Разрешает `RP_ID`, не равный host `APP_URL`, вне dev. Расширяет WebAuthn scope; включать осознанно. |
| `DATABASE_URL` | `sqlite://authlayer.db?mode=rwc` | SQLite URL. WAL, foreign keys и busy timeout 5s включаются кодом; query/userinfo редактируются в логах. |
| `OTP_SECRET` | обязателен вне dev; в dev — случайный | Секрет для HMAC OTP и recovery-кодов; хешируется SHA-256. Вне `DEV_MODE=true` обязателен, минимум 32 символа, известные placeholder'ы запрещены. В dev можно не задавать — будет случайный секрет на процесс. |
| `COOKIE_NAME` | `__Host-al_session` при `COOKIE_SECURE=true`, иначе `al_session` | Имя session-cookie. В production обязан начинаться с `__Host-`. |
| `COOKIE_SECURE` | `true`, если `APP_URL` на `https` | Флаг `Secure`. В production `false` запрещён; на plain HTTP в dev должен быть `false`. |
| `DEV_MODE` | `false` | Включает `/dev/outbox` и `/api/dev/outbox`; требует loopback `BIND_ADDR`/`APP_URL`, иначе нужен `ALLOW_INSECURE_DEV_MODE=true`. В production — `false`. |
| `ALLOW_INSECURE_DEV_MODE` | `false` | Разрешает `DEV_MODE=true` с не-loopback адресом. Только для изолированной разработки. |
| `ADMIN_TOKEN` | не задан | Включает `/admin/login`; минимум 32 символа. Login создаёт серверную `admin_sessions` (1 час). Пустое значение = admin выключен. |
| `SESSION_TTL_DAYS` | `7` | Абсолютный срок жизни сессии и `Max-Age` cookie, в днях. |
| `SESSION_IDLE_HOURS` | `24` | Idle timeout: сессия невалидна, если не использовалась дольше этого времени. |
| `OTP_TTL_MINUTES` | `10` | TTL email-кода (login и recovery), в минутах. |
| `RECOVERY_CODE_TTL_DAYS` | `365` | Срок жизни recovery-кодов, в днях. |
| `EMAIL_PROVIDER` | `outbox` | `outbox` (письма только в БД) или `smtp` (реальная отправка через `lettre`). `outbox` вне dev требует `ALLOW_OUTBOX_WITHOUT_DEV=true`. |
| `ALLOW_OUTBOX_WITHOUT_DEV` | `false` | Разрешает `EMAIL_PROVIDER=outbox` при `DEV_MODE=false`; коды не доставляются. |
| `SMTP_HOST` | — | Обязателен при `EMAIL_PROVIDER=smtp`: хост SMTP-сервера. |
| `SMTP_PORT` | `587` | TCP-порт 1–65535. При `SMTP_TLS=required` и порту `465` используется implicit TLS, иначе STARTTLS. |
| `SMTP_USERNAME` | не задан | Опционально; задаётся вместе с `SMTP_PASSWORD`. |
| `SMTP_PASSWORD` | не задан | Опционально; задаётся вместе с `SMTP_USERNAME`; не логируется. |
| `SMTP_FROM` | — | Обязателен при `EMAIL_PROVIDER=smtp`: mailbox отправителя; валидируется на старте. |
| `SMTP_TLS` | `required` | `required` обязателен в production. `opportunistic` только dev и без credentials; `none` только dev с warning. |
| `TRUST_PROXY` | `false` | Доверять `X-Forwarded-For`/`X-Real-IP` только от доверенных прокси. |
| `TRUSTED_PROXY_CIDRS` | — | Обязателен при `TRUST_PROXY=true`: список CIDR через запятую. |

SMTP-переменные читаются только при `EMAIL_PROVIDER=smtp`; `SMTP_USERNAME` и `SMTP_PASSWORD`
должны быть заданы вместе. `SMTP_FROM` должен быть валидным mailbox. Пароль не логируется.
Вне dev обязательны: `APP_URL=https://...`, `COOKIE_SECURE=true`,
`COOKIE_NAME=__Host-...`, `OTP_SECRET` длиной 32+, `RP_ID == APP_URL host` (если не
`ALLOW_RP_ID_PARENT=true`), `SMTP_TLS=required` при SMTP. `SMTP_TLS=opportunistic`
запрещён вне dev и с credentials. `TRUSTED_PROXY_CIDRS` обязателен при `TRUST_PROXY=true`.
Невалидные значения и неположительные TTL приводят к ошибке старта. `ADMIN_TOKEN` должен
быть не короче 32 символов. `DATABASE_URL` в логах редактируется (query/userinfo).

## Структура проекта

```text
authlayer/
├─ Cargo.toml
├─ Cargo.lock
├─ Dockerfile
├─ docker-compose.yml
├─ .env.example
├─ .dockerignore
├─ migrations/
│  ├─ 0001_init.sql          # users, otp_codes, passkeys, sessions,
│  │                         # recovery_codes, outbox, audit_events
│  ├─ 0002_security_hardening.sql  # passkey_id, stepup_at, code expiry
│  └─ 0003_legacy_and_cookie.sql   # legacy invalidation, passkeys.counter, admin_sessions
├─ src/
│  ├─ main.rs                # tracing, config, DB, WebAuthn, email, cleanup, HTTP server
│  ├─ config.rs              # env, SMTP, TTL, proxy, security flags
│  ├─ db.rs                  # SqlitePool (WAL), миграции, audit, outbox cleanup
│  ├─ auth.rs                # OTP/recovery, advisory failures, sessions, step-up, IP/UA
│  ├─ email.rs               # EmailSender: outbox или SMTP через lettre
│  ├─ state.rs               # AppState, in-memory challenges, cleanup, rate limiter
│  ├─ routes.rs              # Axum router, admin login, все handlers
│  └─ error.rs               # AppError → JSON
├─ static/                   # встроено в бинарник через include_str!
│  ├─ index.html
│  ├─ app.js
│  └─ style.css
├─ deploy/
│  ├─ README.md              # Docker Compose и systemd
│  ├─ Caddyfile
│  └─ authlayer.service
├─ scripts/
│  ├─ README.md              # HTTP smoke test
│  └─ smoke.mjs
├─ docs/
│  └─ IMPLEMENTATION.md      # как это устроено внутри
├─ README.md
└─ target/                   # артефакты сборки, не часть поставки
```

## Docker

Docker image собран: бинарник **13.7 MB**, read-only container healthy. Полная инструкция:
[`deploy/README.md`](deploy/README.md); в репозитории есть `Dockerfile`,
`docker-compose.yml`, `deploy/Caddyfile` и `deploy/authlayer.service`.

Кратко: скопируйте `.env.example` в `.env`, задайте `APP_URL=https://...`, `RP_ID`
(host из `APP_URL`), `OTP_SECRET` (32+), `COOKIE_SECURE=true`,
`COOKIE_NAME=__Host-al_session`, `DEV_MODE=false`, `EMAIL_PROVIDER=smtp` и `SMTP_*`,
замените домен в `deploy/Caddyfile`, затем `docker compose up -d --build`. Наружу
публикуется только Caddy; порт 8080 не открывайте.

За Caddy задайте `TRUST_PROXY=true` и `TRUSTED_PROXY_CIDRS` с сетью прокси. Production
требует HTTPS, `__Host-` cookie и `Origin` на state-changing запросах. `EMAIL_PROVIDER=outbox`
при `DEV_MODE=false` не стартует без `ALLOW_OUTBOX_WITHOUT_DEV=true` и не доставляет коды.
Локальный SMTP E2E через Mailpit прошёл; внешний провайдер не тестировался.

## Разработка

```bash
cargo check          # проверка типов
cargo run            # запуск
RUST_LOG=authlayer=debug,tower_http=debug cargo run
```

Полезно знать:

- Миграции встроены в бинарник через `sqlx::migrate!`; после изменения `migrations/`
  нужна пересборка.
- SQLite-файл по умолчанию — `authlayer.db` в рабочем каталоге. Для сброса dev-БД
  остановите сервер и удалите `authlayer.db` (и `-wal`/`-shm`, если появятся).
- `static/` встроен при компиляции: правки видны только после пересборки.
- HTTP smoke: `node scripts/smoke.mjs` при запущенном сервере; см.
  [`scripts/README.md`](scripts/README.md). WebAuthn/step-up и recovery не покрываются;
  admin login/logout проверяются при заданном `ADMIN_TOKEN`.
- Сервер не делает graceful shutdown: по Ctrl+C незавершённые WebAuthn-церемонии теряются,
  это ожидаемо для v0.1.

## Roadmap

Порядок из `../PROJECT_STATE.md`; это планы, а не обещания текущего релиза.

| Направление | Сейчас | Дальше |
|---|---|---|
| Сборка | `cargo check/build/fmt` проходят; 0 тестов | покрыть тестами |
| Frontend | UI на vanilla JS | локализация, полировка, browser matrix |
| Docker | image собран: 13.7 MB binary, read-only container healthy | проверить compose/Caddy, restore drill, non-root volume и healthcheck |
| Тесты | smoke 26/21; browser E2E 18/18 с virtual authenticator; `cargo test` — 0 тестов | unit/integration + CI/real-device browser matrix |
| Security review | round 3: unrestricted public NO-GO, conditional GO | внешний аудит и проверка фиксов |
| SMTP | Mailpit E2E прошёл; внешний провайдер не тестировался | внешний провайдер, retry/bounce, шаблоны |
| Rate limits | in-memory, auth endpoints | общий store и multi-instance |
| Step-up | WebAuthn для sensitive actions, окно 5 минут | покрыть тестами и UI-интеграцией |
| SQLite | WAL, foreign keys, busy timeout | backup/restore drill, retention, multi-instance |
| Postgres | SQLite | миграция схемы, multi-instance |
| DPoP/DBSC | bearer cookie + passkey-bound sessions | proof-of-possession, привязка cookie к устройству |
| Admin | серверные `admin_sessions`, read-only | роли, 2FA, действия: блокировка, отзыв, удаление |
| Account lifecycle | нет | смена email, удаление аккаунта |
| Multi-tenancy | нет | tenants, отдельные RP ID/origin |

## Лицензия

Проект распространяется под **Apache-2.0**; текст лицензии — [`../LICENSE`](../LICENSE)
в корне репозитория. В каталоге `authlayer/` отдельного файла `LICENSE` нет.

## См. также

- [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) — архитектура, потоки, модель данных,
  challenge state, ошибки, расширение и hardening checklist.
- [`../PROJECT_STATE.md`](../PROJECT_STATE.md) — снимок состояния workstream'ов и known gaps
  на 2026-11-23. Он может отставать от текущего дерева; актуальное поведение описано в
  этом README и `docs/IMPLEMENTATION.md`.
- [`SECURITY_REVIEW_ROUND3.md`](SECURITY_REVIEW_ROUND3.md) — текущий round-3 review:
  unrestricted public **NO-GO**, conditional GO; содержит R3-1…R3-5 и R2 residuals.
- [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) — исторический внутренний review, не текущий
  verdict.
- [`../docs/PRODUCT.md`](../docs/PRODUCT.md) и
  [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) — проектные документы.
  Они описывают целевую архитектуру, и не все их пункты реализованы в v0.1.
