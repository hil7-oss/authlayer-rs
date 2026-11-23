# Кто уже это делал и что брать готовое

## TL;DR

- **Passkeys/WebAuthn** — готовый стандарт для входа без пароля в свои приложения.
- **Push-подтверждение** — готовый паттерн для «подтверди на телефоне» (Duo, Okta Verify, CIBA).
- **Passwordless для legacy-сайтов** — уже делают Keeper, 1Password, 1Kosmos, IamLogic, My1Login, CyberArk, Delinea: расширение + автозаполнение после passwordless-входа.
- **SSH без паролей** — Teleport, Tailscale SSH, Smallstep, Vault SSH, Boundary.
- **Sealed delivery / одноразовые секреты** — Vault/OpenBao, Infisical, SOPS+age.
- **Device-bound сессии** — Google DBSC, Microsoft Token Protection, DPoP, mTLS.
- **Отдельного продукта, который делает всё вместе** (письмо с зашифрованным паролем → доверенное устройство → автозаполнение на чужом сайте → SSH), нет. Это композиция; свободная ниша — интеграция и UX, а не криптография.

---

## 1. Passkeys / WebAuthn

### Что это

WebAuthn — стандарт W3C/FIDO2. Вместо пароля — пара ключей: private в TPM/Secure Enclave/Keystore, public на сервере. Аутентификация — подпись challenge, привязанная к origin. Passkey — удобная обёртка (synced или device-bound).

### Кто

- Apple (iCloud Keychain), Google (Password Manager), Microsoft (Windows Hello).
- FIDO Alliance, W3C.
- Библиотеки: SimpleWebAuthn (Node), go-webauthn, py_webauthn, webauthn4j, fido2-lib.
- Провайдеры: Hanko, Corbado, Stytch, Auth0, Clerk, WorkOS, Descope, Passage (1Password).

### Что взять

- **SimpleWebAuthn** для Node/TS;
- **go-webauthn** для Go;
- **py_webauthn** для Python;
- не писать свою проверку attestation/assertion.

### Ограничение

Passkeys работают только там, где сервер поддерживает WebAuthn. Для чужих legacy-сайтов они не помогут. Для enterprise нужна политика device-bound vs synced passkeys (attestation, AAGUID allowlist).

---

## 2. Magic links / email OTP

### Что это

Ссылка или код на email. Пользователь кликает — получает сессию. Просто, но:

- plaintext-ссылка = bearer-токен;
- доступ к email = захват аккаунта;
- ссылку можно переслать/перехватить;
- email-провайдер видит токен;
- фишинг.

### Кто

Auth0, Stytch, Magic, Clerk, WorkOS, Supabase Auth, Firebase Auth.

### Почему не подходит под требование

Это ровно то, что пользователь хочет исключить: «у злоумышленника есть доступ к почте — пароль ему не подойдёт». Magic link в чистом виде этому не удовлетворяет.

### Что можно улучшить

- **device-bound magic link**: ссылка ведёт на страницу, которая требует ключ устройства; токен в ссылке — только ID запроса, не секрет;
- **sealed delivery**: email несёт шифротекст, а не bearer-токен;
- **push approval**: email только уведомляет, подтверждение — на устройстве.

Это уже не «magic link» в классическом смысле, а комбинация с device binding.

---

## 3. Push-подтверждение и CIBA

### Что это

Пользователь инициирует вход на одном устройстве, подтверждает на другом (телефон). Push + number matching + биометрия.

### Кто

- Cisco Duo Push;
- Okta Verify;
- Microsoft Authenticator;
- Authsignal;
- PingID, RSA SecurID;
- OpenID Connect CIBA (Client-Initiated Backchannel Authentication) — стандарт для decoupled flow;
- банковские приложения (PSD2 SCA).

### Что взять

- CIBA как модель протокола;
- Duo/Authsignal, если нужен готовый push;
- для MVP — Telegram-бот с подписанным approval (не просто «нажми кнопку»).

### Ограничение

Push approval — это второй фактор/подтверждение, а не замена пароля. Если push-запрос не подписан устройством и не привязан к контексту, его можно подделать/заспамить. Нужны:

- context binding (origin, resource, amount);
- number matching;
- rate limit;
- device key signature.

---

## 4. Passwordless для legacy-приложений

Это самый близкий к идее пользователя сегмент.

### Как работает

1. Пользователь входит в PAM/SSO без пароля (passkey, SSO).
2. Браузерное расширение получает доступ к хранилищу.
3. Расширение автозаполняет логин/пароль legacy-приложения.
4. Пароль остаётся в хранилище, но пользователь его не вводит.

### Кто

- **Keeper** — KeeperFill, passwordless для legacy;
- **1Password** — расширение + passkeys + enterprise;
- **1Kosmos** — Chrome extension + passkey/LiveID;
- **IamLogic** — passwordless + расширение заполняет форму;
- **My1Login** — Chrome SSO extension для legacy;
- **CyberArk**, **Delinea**, **BeyondTrust** — PAM с credential injection;
- **Passwordstate**, **TeamPassword** — team vaults.

### Что это значит

Идея «не вводить пароль руками, а получать его из источника и автозаполнять» **уже коммерциализирована**. Но это по сути password manager/PAM с passwordless-разблокировкой, а не «пароль перестал существовать». Для сайтов, которые не поддерживают passkeys, пароль остаётся.

### Чем можно дифференцироваться

- **sealed delivery**: пароль не хранится в расширении, а выдаётся по запросу после approval на доверенном устройстве;
- **one-time / rotation**: пароль меняется после каждого использования;
- **SSH + web + self-hosted** в одном продукте;
- **open-source / self-hosted** для homelab/DevOps;
- **no master password**: ключ устройства вместо мастер-пароля.

---

## 5. SSH без паролей

### Что это

Вместо статических ключей/паролей — короткоживущие SSH-сертификаты, выданные после SSO/WebAuthn. Или identity-based доступ через mesh/VPN.

### Кто

| Продукт | Модель | Плюсы | Минусы |
|---|---|---|---|
| **Teleport** | прокси + короткие сертификаты + RBAC + audit | полный продукт, WebAuthn, apps/db/k8s | тяжёлый, коммерческий |
| **Tailscale SSH** | identity tailnet + ACL | просто, без ключей | нужен Tailscale на всех хостах; как любую сеть, её нужно патчить |
| **Smallstep step-ca** | CA + OIDC + короткие сертификаты | лёгкий, стандартный SSH | меньше UX/аудита |
| **Vault SSH** | secrets engine, OTP/сертификаты | интеграция с Vault | OTP — снова пароль |
| **Boundary** | прокси + сессии | audit, RBAC | тяжёлый |
| **StrongDM** | коммерческий access plane | UX | дорого |

### Что взять

- **step-ca** для MVP: `step ssh login` + OIDC + короткие сертификаты;
- **Teleport** если нужен полный audit/RBAC/apps;
- **Tailscale SSH** если сеть уже на Tailscale и нужен быстрый старт;
- **OpenSSH CA** (`TrustedUserCAKeys`) — стандарт, не изобретать.

### Ограничение

Если сервер поддерживает только password auth, придётся либо включать CA, либо брокерить пароль. Брокерить SSH-пароль — худший вариант: пароль попадает на рабочую станцию. Лучше изменить конфиг сервера.

---

## 6. Sealed delivery и одноразовые секреты

### Что это

Секрет выдаётся один раз, на короткий срок, после проверки. В идеале — зашифрован на получателя.

### Кто

- **HashiCorp Vault / OpenBao** — dynamic secrets, response wrapping, PKI, SSH;
- **Infisical** — developer-friendly secrets;
- **SOPS + age** — статические секреты в git;
- **AWS/GCP/Azure Secret Manager** — cloud secrets;
- **1Password/Bitwarden Send** — одноразовые ссылки (но bearer);
- **Teleport** — короткие сертификаты;
- **SPIFFE/SPIRE** — workload identity.

### Что взять

- **Vault response wrapping** — идея «wrap token»;
- **Vault dynamic secrets** — одноразовые DB-креды;
- **Infisical** для MVP, если нужен простой UI/API;
- **HPKE/JWE** для шифрования на устройство.

### Ограничение

Vault не решает «доставку в email/мессенджер» и «approval на телефоне». Это нужно строить поверх.

---

## 7. Device-bound сессии

### Что это

Сессия/токен привязан к ключу устройства; кража куки/токена не даёт доступа.

### Кто

- **Google DBSC** — Chrome 146+ Windows, macOS rollout; TPM/Secure Enclave; W3C;
- **Microsoft Token Protection** — Conditional Access;
- **DPoP** — RFC 9449; Auth0, WorkOS, Curity, Nimbus;
- **mTLS** — enterprise;
- **FIDO2/WebAuthn** — вход;
- **OAuth 2.1 / FAPI 2.0** — рекомендуют sender-constrained tokens.

### Что взять

- DPoP для API/CLI (`jose`, oauth4webapi);
- DBSC для браузера, где поддерживается;
- fallback: opaque session + WebAuthn step-up + risk;
- не выдавать ключи расшифровки клиенту.

### Ограничение

DBSC пока не везде. Для старых браузеров/ОС — компромисс: короткий TTL, rotation, revoke, risk.

---

## 8. Рынок и консолидация

| Событие | Что показывает |
|---|---|
| **Clef** — phone-based passwordless login, куплен Twilio в 2017, закрыт | идея была, рынок не был готов; distribution решает |
| **KryptCo / Krypton** — телефон как ключ для SSH/U2F, технология куплена Akamai в 2019, стала Akamai MFA | «телефон подтверждает SSH» уже было |
| **Stytch** — passwordless API, куплен Twilio в ноябре 2025 | рынок консолидируется; чистый passwordless — commodity |
| **Passage** — passkeys, куплен 1Password | passkeys стали фичей password manager |
| **OwnID** — passwordless, куплен Unico | ниша CIAM |
| **Magic** — magic links | ниша, но email-зависимость |
| **Hanko, Corbado, Descope, Authsignal** | passkey/passwordless/anti-fraud |

### Вывод

- «Ещё один passwordless API» — сложно: конкуренты дешёвые, крупные, с distribution.
- «Passwordless для legacy + SSH + self-hosted + sealed delivery» — более узкая и защищённая ниша.
- «Библиотека, которую можно вставить в любое приложение» — хороший self-hosted/DevOps продукт, но не массовый consumer.
- Для одного разработчика реалистичнее: **open-source инструмент для homelab/DevOps** (SSH + админки + Telegram approval), а не конкуренция с Auth0.

---

## 9. Build vs buy

| Компонент | Готовое | Своё | Рекомендация |
|---|---|---|---|
| WebAuthn | SimpleWebAuthn, go-webauthn, py_webauthn | нет | брать |
| OAuth/OIDC | Keycloak, Ory Hydra, Zitadel | нет | брать |
| Сессии | iron-session, express-session, Spring Session | обвязка | брать + device binding |
| DPoP | jose, oauth4webapi | нет | брать |
| DBSC | спецификация/браузер | серверные endpoint'ы | реализовать, где нужно |
| SSH CA | step-ca, Teleport | нет | брать |
| Secrets | Vault/OpenBao, Infisical, SOPS | нет | брать |
| Push | Duo, Authsignal, CIBA | Telegram для MVP | брать/интегрировать |
| Email | SES, Postmark, Mailgun | нет | брать |
| Messaging | Telegram Bot API, Signal, Matrix | обвязка | брать |
| Browser extension | WebExtension API | да, тонкое | своё |
| Crypto | libsodium, JOSE, HPKE | нет | брать |
| KMS | AWS KMS, Vault Transit, YubiHSM | нет | брать |
| Policy | OPA, Cedar | позже | брать при росте |
| Audit | Postgres, S3 Object Lock, SIEM | обвязка | брать |
| Gateway | Caddy, Nginx, Traefik, Envoy | плагин | брать |
| Reverse-proxy auth | oauth2-proxy, Authelia, Authentik, Pomerium | нет | изучить/интегрировать |

---

## 10. Рекомендуемый стек для MVP

| Слой | Выбор | Почему |
|---|---|---|
| Язык | TypeScript (Fastify) + Go (gateway) | скорость + один бинарник |
| БД | Postgres 16 | надёжно, JSONB, партиции |
| Кэш/сессии | Redis 7 | TTL, rate limit |
| IdP | Keycloak или Ory Kratos | passkeys, OIDC, self-hosted |
| WebAuthn | SimpleWebAuthn | зрелый |
| Крипто | node:crypto + jose | Ed25519, X25519, JWE |
| SSH CA | step-ca | лёгкий, OIDC |
| Доставка | Telegram Bot API + SES | быстро, дёшево |
| Gateway | Caddy + plugin | TLS из коробки |
| Extension | MV3 + native messaging | тонкое |
| KMS | Vault Transit / AWS KMS | ключи |
| Аудит | Postgres + S3 Object Lock | immutable |
| Деплой | Docker Compose | просто |

---

## 11. Позиционирование

### Не конкурировать с

- Auth0/Clerk/WorkOS в «login for SaaS»;
- 1Password/Bitwarden в «password manager»;
- Teleport в «enterprise access plane» (сразу).

### Ниша

1. **Self-hosted passwordless access для DevOps/homelab**: SSH + админки + Telegram approval.
2. **Open-source библиотека для своих приложений**: passkeys + device-bound sessions + sealed delivery.
3. **Legacy broker для команд**: свои сайты, где нет SSO, но есть безопасность.
4. **Приватность**: без облака, без мастер-пароля, ключи на устройствах.

### УТП

- «Пароль больше не вводится руками» — для своих систем.
- «Письмо с паролем бесполезно без твоего устройства» — sealed delivery.
- «SSH без статических ключей» — сертификаты.
- «Один слой для веба и SSH» — интеграция.
- «Self-hosted, без вендора» — контроль.

---

## 12. Что сказать пользователю, который спросит «а это уже есть?»

Да, по частям:

- passkeys — есть;
- push approval — есть;
- passwordless legacy autofill — есть у PAM/менеджеров;
- SSH certs — есть;
- sealed email — есть как концепция (Vault wrapping, S/MIME, age), но не как массовый продукт;
- всё вместе — нет.

Поэтому проект имеет смысл как **интеграционный слой** и **UX-продукт**, а не как новая криптография. Если цель — «сделать себе», проще собрать из готовых частей. Если цель — «продать», нужна узкая ниша и доверие.
