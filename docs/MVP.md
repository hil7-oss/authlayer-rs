# MVP: пошаговый план

> **Статус документа:** исторический roadmap/план. Фактическая реализация v0.1 — в `authlayer/` (Rust + Axum + SQLite + passkeys + email OTP + step-up + Docker). SSH, legacy-брокер, Postgres/Redis, DPoP/DBSC и ML пока не реализованы; см. `PROJECT_STATE.md`.

## Цель MVP

Доказать три вещи на одном стенде Ubuntu:

1. **Библиотека/шлюз реально встраивается** в приложение и защищает сессии (7 дней, device binding, отзыв).
2. **SSH работает без пароля** через короткоживущие сертификаты.
3. **Письмо/сообщение с секретом бесполезно без доверенного устройства** (sealed delivery + approval).

Всё остальное — позже.

---

## Что входит в MVP

| Компонент | Входит |
|---|---|
| Passkeys/WebAuthn | да |
| Opaque server-side sessions | да |
| 7-дневный refresh + rotation | да |
| DPoP для API/CLI | да |
| DBSC | поддержка endpoint'ов, если браузер умеет; fallback |
| Device enrollment + revoke | да |
| Sealed delivery | да |
| SSH certificates | да |
| Legacy autofill | да, минимально |
| Admin UI | минимально |
| Audit | да |
| Multi-tenant | нет |
| Мобильное приложение | нет (Telegram/веб для MVP) |
| Billing | нет |

## Что не входит

- Kubernetes/DB access;
- social recovery;
- enterprise SSO (SAML/LDAP);
- мобильные SDK;
- сложная политика (OPA);
- сертификация SOC2/ISO;
- поддержка всех языков/фреймворков.

---

## Фазы

### Phase 0. Решения и спайк (2–3 дня)

- [ ] Выбрать главный сценарий: SSH + свои веб-приложения.
- [ ] Зафиксировать threat model (см. ARCHITECTURE.md).
- [ ] Проверить `step-ca` + OIDC за полдня.
- [ ] Проверить `SimpleWebAuthn` за полдня.
- [ ] Проверить `jose` JWE/HPKE за полдня.
- [ ] Решить: телефон как отдельное устройство или ноутбук.
- [ ] Решить: Telegram или email для MVP (можно оба).

**Выход:** короткий ADR (architecture decision record) на 1 страницу.

### Phase 1. SDK + Gateway + сессии (1.5–2 недели)

- [ ] `@authlayer/core`: ключи, JWE, канонический JSON, подписи.
- [ ] `@authlayer/server`: accounts, devices, sessions, audit.
- [ ] WebAuthn: регистрация/вход через SimpleWebAuthn.
- [ ] Opaque session cookie: `__Host-`, Secure, HttpOnly, SameSite.
- [ ] Session store: Postgres + Redis.
- [ ] Refresh rotation + reuse detection.
- [ ] DPoP: выдача/проверка proof.
- [ ] Middleware для Fastify/Express.
- [ ] `authlayerd` gateway: `/verify` + заголовки.
- [ ] Caddy forward-auth пример.
- [ ] Demo app: страница входа, `/api/me`, protected route.
- [ ] Тесты: cookie theft, DPoP replay, refresh reuse, revoke.

**Демо:**

```bash
docker compose up -d
open https://demo.localhost
# регистрация passkey → вход → /api/me
# curl без DPoP → 401
# украсть куку в другом браузере → 401 (или короткий TTL)
```

**Критерии приёмки:**

- вход без пароля;
- кука не читается JS;
- API без DPoP не работает;
- отзыв устройства инвалидирует сессию;
- 7-дневный refresh работает, access истекает;
- gateway закрывает приложение, прямой доступ blocked.

### Phase 2. SSH без пароля (1.5–2 недели)

- [ ] `step-ca` в Docker Compose.
- [ ] OIDC/device flow для CLI.
- [ ] `authlayer ssh <host>`: запрос сертификата.
- [ ] Выдача SSH user cert (5–15 мин) с principal.
- [ ] `TrustedUserCAKeys` на тестовом хосте.
- [ ] `PasswordAuthentication no`.
- [ ] Telegram approval для prod (опционально).
- [ ] Audit: кто, когда, какой хост, какой cert.
- [ ] Тесты: expiry, principal, revoke, no password.

**Демо:**

```bash
authlayer login
authlayer ssh demo@prod-1
# без пароля, сертификат на 10 минут
ssh-keygen -L -f /tmp/cert.pub
# через 10 минут — отказ
```

**Критерии приёмки:**

- на сервере нет статических ключей;
- сертификат живёт ≤ 15 минут;
- отозванное устройство не получает новый сертификат;
- audit содержит все выдачи.

### Phase 3. Sealed delivery + legacy autofill (2–3 недели)

- [ ] `POST /access-requests`.
- [ ] Шифрование секрета на X25519 ключ устройства.
- [ ] Email/Telegram доставка только шифротекста.
- [ ] Страница/приложение устройства: расшифровка, контекст, approve.
- [ ] Подпись approval, проверка на сервере.
- [ ] One-time claim + TTL 60 сек.
- [ ] Browser extension MV3: кнопка, native messaging, autofill.
- [ ] Локальный агент: получение секрета, заполнение, очистка.
- [ ] Ротация пароля (если есть API) или отметка used.
- [ ] Audit: request → approval → claim → use.

**Демо:**

```text
1. Открыть legacy admin panel (demo).
2. Нажать "Unlock with AuthLayer".
3. В Telegram приходит шифротекст.
4. На телефоне/втором устройстве — контекст + approve.
5. Пароль автозаполняется, вход выполняется.
6. Повторно использовать пароль нельзя.
```

**Критерии приёмки:**

- в письме/Telegram нет plaintext-пароля;
- без private key устройства расшифровка невозможна;
- повторный claim → ошибка;
- approval без подписи → отказ;
- отзыв устройства → отказ;
- пароль не хранится в extension после заполнения.

### Phase 4. Hardening и упаковка (1–2 недели)

- [ ] Admin UI: устройства, сессии, audit, revoke.
- [ ] Recovery key + процедура восстановления.
- [ ] Rate limiting, lockout, anomaly alerts.
- [ ] KMS/Vault Transit для ключей.
- [ ] Docker image + `.deb` + systemd.
- [ ] Caddy plugin / Nginx config.
- [ ] Документация: quickstart, API, security.
- [ ] E2E тесты в CI.
- [ ] SBOM, dependency scan, signed releases.

---

## Архитектура MVP

```text
┌──────────────────────────────────────────────────────────────┐
│                        Caddy (TLS)                           │
│  forward_auth → authlayerd                                   │
└───────────────┬──────────────────────────────┬───────────────┘
                │                              │
      ┌─────────▼─────────┐          ┌─────────▼─────────┐
      │ demo-web          │          │ legacy-demo       │
      │ (Fastify/Next)    │          │ (форма логина)    │
      └─────────┬─────────┘          └─────────┬─────────┘
                │                              │
      ┌─────────▼─────────┐          ┌─────────▼─────────┐
      │ @authlayer/server │          │ extension + agent │
      └─────────┬─────────┘          └─────────┬─────────┘
                │                              │
      ┌─────────▼──────────────────────────────▼─────────┐
      │              authlayerd (Go)                      │
      │  accounts · devices · sessions · broker · audit   │
      └───────┬───────────────────────┬───────────────────┘
              │                       │
      ┌───────▼───────┐       ┌───────▼───────┐
      │ Postgres      │       │ Redis         │
      └───────────────┘       └───────────────┘
              │
      ┌───────▼───────┐       ┌───────────────┐
      │ step-ca       │       │ Telegram/SES  │
      └───────────────┘       └───────────────┘
```

---

## Репозиторий

```text
autorization/
├── apps/
│   ├── authlayerd/          # Go gateway/IdP
│   ├── demo-web/            # Fastify/Next demo
│   ├── legacy-demo/         # форма логина для autofill
│   ├── cli/                 # authlayer CLI
│   └── extension/           # MV3 extension
├── packages/
│   ├── core/                # TS: crypto, JWE, types
│   ├── server/              # TS: SDK
│   ├── express/             # adapter
│   ├── fastify/             # adapter
│   ├── next/                # adapter
│   ├── react/               # UI
│   └── python/              # Python SDK (FastAPI/Django)
├── infra/
│   ├── docker-compose.yml
│   ├── Caddyfile
│   ├── step-ca/
│   ├── keycloak/
│   └── migrations/
├── tests/
│   ├── e2e/
│   ├── crypto/
│   └── security/
└── docs/
```

---

## Стек

| Слой | Выбор |
|---|---|
| SDK | TypeScript, Fastify, `jose`, `@simplewebauthn/server`, `pg`, `ioredis`, `zod` |
| Gateway | Go, `chi`, `pgx`, `go-webauthn`, `redis` |
| Python SDK | FastAPI/Django, `py_webauthn` |
| БД | Postgres 16 |
| Кэш | Redis 7 |
| Прокси | Caddy 2 |
| SSH CA | step-ca |
| Доставка | Telegram Bot API + SES/Postmark |
| Extension | Chrome MV3, native messaging |
| Тесты | Vitest, Playwright, Go test, pytest |
| Деплой | Docker Compose, .deb, systemd |
| Наблюдаемость | OpenTelemetry, Prometheus, Grafana, Loki |

---

## Установка на Ubuntu (целевой UX)

```bash
# 1. Docker
curl -fsSL https://get.docker.com | sh

# 2. AuthLayer
mkdir authlayer && cd authlayer
curl -fsSL https://get.authlayer.dev/install.sh | sh

# 3. Конфиг
authlayer init --domain auth.example.com

# 4. Запуск
docker compose up -d

# 5. Админ
authlayer admin create --email admin@example.com

# 6. Проверка
curl https://auth.example.com/healthz
```

Для embedded:

```bash
npm install @authlayer/server @authlayer/express
```

```ts
import { AuthLayer } from '@authlayer/server';
const auth = new AuthLayer({ /* config */ });
app.use(auth.middleware());
```

---

## План тестов

### Криптография

- [ ] Sealed envelope: tamper → fail.
- [ ] Wrong device key → fail.
- [ ] Expired envelope → fail.
- [ ] Replay request_id → fail.
- [ ] Server signature invalid → fail.
- [ ] Approval signature invalid → fail.
- [ ] Nonce reuse → fail.

### Сессии

- [ ] Cookie flags.
- [ ] Cookie theft without DPoP → 401.
- [ ] DPoP proof replay → 401.
- [ ] `htu`/`htm` mismatch → 401.
- [ ] Refresh reuse → family revoke.
- [ ] 7-day absolute expiry.
- [ ] Idle timeout.
- [ ] Revoke device → 401.
- [ ] Session fixation → new ID.
- [ ] CSRF.
- [ ] XSS (CSP).

### Enrollment

- [ ] Email-only → cannot activate.
- [ ] Existing device approval → success.
- [ ] Revoked device cannot approve.
- [ ] Delay for high-risk.

### SSH

- [ ] Cert expiry.
- [ ] Principal mapping.
- [ ] Source address.
- [ ] Revoked device → no new cert.
- [ ] Password auth disabled.
- [ ] Audit.

### Legacy

- [ ] No plaintext in email/Telegram.
- [ ] One-time claim.
- [ ] Rotation.
- [ ] Extension clears secret.
- [ ] Approval context.
- [ ] Wrong origin → fail.

### Gateway

- [ ] Header spoof stripped.
- [ ] Direct app access blocked.
- [ ] Fail closed on authlayerd down.
- [ ] mTLS/localhost.

---

## Оценка

| Phase | Один опытный разработчик |
|---|---|
| 0 | 2–3 дня |
| 1 | 8–12 дней |
| 2 | 8–12 дней |
| 3 | 15–20 дней |
| 4 | 10–15 дней |
| **Итого MVP** | **~6–10 недель** |
| Production-ready | 3–6 месяцев |

Если делать только SSH (Phase 0+2), можно уложиться в 2–3 недели. Если только библиотеку/сессии (Phase 0+1) — 2 недели.

---

## Риски MVP

| Риск | Вероятность | Митигация |
|---|---|---|
| Scope creep | высокая | фиксировать phases, не добавлять DB/K8s |
| Сложность step-ca | средняя | спайк в Phase 0; fallback Teleport |
| Browser extension review | средняя | dev-mode/enterprise install; не Chrome Store сразу |
| DBSC не везде | высокая | fallback на opaque session + step-up |
| Telegram блокировки | средняя | email fallback; push позже |
| Крипто-ошибки | средняя | использовать jose/libsodium, тест-векторы, review |
| Recovery | средняя | recovery key + задержка; не email-only |
| UX подтверждений | высокая | контекст, number matching, тесты с людьми |
| Юридические ограничения | низкая/средняя | использовать только свои аккаунты; ToS |
| Поддержка фреймворков | высокая | начать с Fastify/Express + gateway, не обещать всё |

---

## Что делать дальше

1. Ответить на открытые вопросы из ARCHITECTURE.md (сценарий, устройство, self-hosted).
2. Сделать Phase 0: спайк step-ca + SimpleWebAuthn + jose.
3. Собрать Phase 1: SDK + gateway + passkeys + сессии.
4. Показать демо: украденная кука не работает, устройство отзывается, 7 дней.
5. Собрать Phase 2: SSH без пароля.
6. Собрать Phase 3: sealed delivery + extension.
7. Решить, продукт это или личный инструмент.

---

## Минимальное демо на 5 минут

```text
1. Регистрация passkey → вход.
2. Показать cookie: HttpOnly, Secure, __Host-.
3. Скопировать cookie в другой браузер → 401 (DPoP/DBSC/revoke).
4. Отозвать устройство → сессия мертва.
5. authlayer ssh prod → сертификат на 10 минут, без пароля.
6. Открыть legacy admin → approval в Telegram → автозаполнение.
7. Показать письмо: только шифротекст.
8. Повторно использовать пароль → нельзя.
```

Это и есть доказательство идеи.
