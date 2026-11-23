# Сессии и куки: почему шифрования недостаточно

Это ответ на идею: «шифруем куки сессии нашим ключом, и куки нельзя расшифровать, пока устройство не получит ключ и дешифратор не определит, что оно имеет право».

Короткий ответ: **шифрование куки защищает содержимое, но не защищает от кражи и повторного использования.** Кука — это bearer-токен. Чтобы украденная кука не работала, её нужно привязать к ключу устройства криптографически (proof of possession), а не просто зашифровать.

---

## 1. Что предлагается

```text
Сервер шифрует куку ключом K.
Браузер хранит шифротекст.
На каждый запрос сервер расшифровывает куку ключом K.
Если устройство «имеет право» — сервер выдаёт ему ключ K или расшифрованные данные.
```

Проблемы:

1. **Куда девается K?** Если K на сервере — компрометация сервера = расшифровка всех кук. Если K у клиента — его можно украсть (XSS, malware, диск). Если K выдаётся клиенту после проверки — атакующий может пройти ту же проверку.
2. **Кто такой «имеет право»?** IP, user-agent, fingerprint — всё подделывается или совпадает у атакующего, если он украл куку с того же устройства. Нужен криптографический секрет, которого у атакующего нет.
3. **Повторное использование.** Даже если кука зашифрована, атакующий может отправить её серверу. Сервер расшифрует и примет, потому что это валидная кука.
4. **Ключ на клиенте.** Если браузер может расшифровать куку, значит, ключ доступен JavaScript/расширению/malware. HttpOnly защищает от чтения куки, но не от запросов от имени пользователя (CSRF/XSS).
5. **7 дней.** Чем дольше живёт bearer-токен, тем больше окно для кражи. Шифрование не сокращает это окно.

---

## 2. Аналогия

- **Кука** — это билет в кино. Шифрование делает билет нечитаемым, но контролёр всё равно пускает любого, у кого есть билет.
- **Device binding** — это билет, привязанный к паспорту. Контролёр проверяет не только билет, но и паспорт (подпись устройства).
- **Шифрование** полезно, чтобы в билете не было видно имени/роли. Но оно не заменяет паспорт.

---

## 3. Правильная модель: proof of possession

Вместо «расшифровать куку и проверить право»:

1. У устройства есть приватный ключ, публичный ключ известен серверу.
2. Сервер выдаёт сессию, привязанную к публичному ключу (`cnf.jkt` для DPoP, DBSC key, mTLS thumbprint).
3. На каждый запрос устройство подписывает challenge/proof.
4. Сервер проверяет подпись. Без приватного ключа украденная кука/токен бесполезны.
5. Ключ никогда не покидает устройство; сервер не «выдаёт право на расшифровку», он проверяет доказательство.

Это стандарты:

- **DPoP** (RFC 9449) — для API/CLI/native.
- **DBSC** — для браузерных кук (Chrome 146+ Windows, macOS rollout).
- **mTLS** — для enterprise.
- **WebAuthn** — для входа и step-up.

---

## 4. Варианты хранения сессии

### Вариант A. Opaque server-side session (рекомендуется)

```http
Set-Cookie: __Host-al_session=<256-bit random>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=604800
```

Сервер:

```text
session_id = random(32 bytes)
store sha256(session_id) -> {account_id, device_id, exp, ...}
```

Плюсы:

- мгновенный отзыв;
- нет PII в куке;
- кража БД не даёт готовых session ID (хранится хеш);
- просто.

Минусы:

- нужен store (Redis/Postgres);
- на каждый запрос — lookup (быстро).

Защита от кражи:

- `HttpOnly` — JS не читает;
- `Secure` — только HTTPS;
- `SameSite=Lax/Strict` — CSRF;
- `__Host-` — запрещает Domain/Path-инъекции;
- короткий TTL + rotation;
- device binding (DPoP/DBSC);
- revoke.

### Вариант B. JWE cookie (stateless)

```text
Set-Cookie: __Host-al_session=<JWE>; ...
JWE: alg=dir/ECDH-ES, enc=A256GCM, kid=...
```

Плюсы:

- нет lookup;
- можно масштабировать без общего store;
- шифрует claims.

Минусы:

- отзыв сложнее (denylist/version);
- 7 дней — плохо для stateless;
- кража = replay до истечения;
- ротация ключей сложнее.

Когда использовать:

- короткие access-сессии (10–15 минут);
- stateless API;
- плюс refresh в server-side store;
- плюс device binding.

### Вариант C. Device-bound session

```text
Cookie: __Host-al_session=<opaque id>
Header: DPoP: <proof JWT> (для API)
или DBSC proof (для браузера)
```

Сервер:

1. по куке находит сессию;
2. проверяет `session.binding_jkt`;
3. проверяет подпись proof;
4. сверяет `htm`, `htu`, `iat`, `jti`, `ath`;
5. только потом пускает.

Это лучший вариант для 7-дневной сессии.

---

## 5. Как сделать 7 дней безопасно

| Параметр | Значение | Почему |
|---|---|---|
| Access token | 10–15 мин | короткое окно кражи |
| Refresh token | 7 дней | удобство |
| Refresh rotation | каждый refresh | reuse detection |
| Absolute session | 7 дней | принудительный re-auth |
| Idle timeout | 24 ч | забытые устройства |
| Device binding | DPoP/DBSC | украденный токен бесполезен |
| Re-auth | WebAuthn/biometric | чувствительные действия |
| Revoke | мгновенно | потеря/компрометация |
| Reuse detection | отзыв family | кража refresh |

Схема:

```text
Login → access(10m) + refresh(7d)
Request → access + DPoP proof
Access expired → refresh + DPoP proof → new access + new refresh (rotation)
Refresh reuse → revoke all sessions of that family
7 days → full re-auth
Device revoked → all sessions invalid
```

---

## 6. Конвейер проверки («дешифратор определяет право»)

Правильная реализация — не выдача ключа, а проверка:

```text
verifySession(request):
  1. cookie = parse(request)
  2. if cookie is JWE: verify AEAD tag + exp + iss + aud
     else: id = cookie; hash = sha256(id); session = store.get(hash)
  3. if !session or session.revoked_at: reject
  4. if now > session.expires_at or now > session.absolute_expires_at: reject
  5. if now - session.last_seen > idle_ttl: reject
  6. device = devices.get(session.device_id)
  7. if device.status != active: reject
  8. if !verifyBinding(request, session): reject
       - DPoP: proof.jkt == session.binding_jkt
       - DBSC: proof valid for session
       - mTLS: cert thumbprint == session.binding_thumbprint
  9. if !user.active or user.locked: reject
 10. if !scopesAllow(request, session.scopes): reject
 11. optional: risk score -> require step-up
 12. rotate refresh if needed; update last_seen
 13. attach user/device to request
```

`verifyBinding` — единственное, что реально защищает от кражи. Всё остальное — гигиена.

---

## 7. DBSC: привязка браузерной куки

DBSC (Device Bound Session Credentials) — механизм Chrome, который привязывает сессию к ключу устройства (TPM на Windows, Secure Enclave на macOS). Как это работает:

1. Сервер при логине создаёт сессию и просит браузер зарегистрировать ключ.
2. Браузер генерирует пару ключей в TPM/Secure Enclave; private не экспортируется.
3. Сервер выдаёт короткоживущую куку.
4. При refresh браузер подписывает challenge ключом.
5. Сервер проверяет подпись и выдаёт новую куку.
6. Украденная кука не может быть обновлена без ключа; срок жизни короткий.

Статус (2026):

- Chrome 146+ на Windows — GA;
- macOS — rollout (Chrome 147+);
- Linux/Android/iOS — позже/нет;
- Google Workspace — можно включить;
- W3C DBSC — спецификация.

Для AuthLayer:

- поддержать DBSC endpoints;
- если браузер не поддерживает — fallback: opaque session + short TTL + WebAuthn step-up + risk;
- не обещать DBSC всем и сразу.

Серверные endpoint'ы DBSC (упрощённо):

```text
POST /dbsc/registration
  -> { session_id, refresh_url, scope }

POST /dbsc/refresh
  Sec-Session-Response: <JWT proof>
  -> new short-lived cookie
```

Точный формат зависит от спецификации; библиотека должна инкапсулировать.

---

## 8. DPoP: привязка API-токена

DPoP proof — JWT, подписанный ключом клиента:

```json
{
  "typ": "dpop+jwt",
  "alg": "EdDSA",
  "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
}
```

```json
{
  "jti": "uuid",
  "htm": "POST",
  "htu": "https://api.example.com/v1/access-requests",
  "iat": 1763900000,
  "ath": "base64url(sha256(access_token))"
}
```

Сервер:

1. проверяет подпись;
2. `htm`/`htu` совпадают;
3. `iat` в пределах 60 секунд;
4. `jti` не использован;
5. `ath` = хеш access token;
6. thumbprint `jwk` = `cnf.jkt` в токене.

Без private key украденный access/refresh бесполезен.

---

## 9. JWE-кука: когда и как

Если всё же нужна зашифрованная кука:

```json
{
  "protected": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6ImsxIn0",
  "encrypted_key": "...",
  "iv": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

Правила:

- `A256GCM`;
- ключ в KMS;
- `kid` для ротации;
- AAD = session id/device id/version;
- TTL 10–15 минут, не 7 дней;
- refresh — server-side;
- device binding обязательна;
- не класть PII без необходимости;
- не использовать `none`/`HS256` с общим секретом в браузере.

Что это даёт:

- конфиденциальность claims;
- integrity;
- stateless.

Что это **не** даёт:

- защиту от кражи/повтора;
- отзыв;
- привязку к устройству.

---

## 10. Чек-лист реализации

### Кука

- [ ] `__Host-` prefix;
- [ ] `Secure`;
- [ ] `HttpOnly`;
- [ ] `SameSite=Lax` (или Strict);
- [ ] `Path=/`;
- [ ] без `Domain`;
- [ ] `Max-Age` ≤ 7 дней;
- [ ] random 256-bit ID;
- [ ] hash в БД;
- [ ] ротация при login/privilege change;
- [ ] очистка при logout/revoke.

### Сессия

- [ ] access 10–15 мин;
- [ ] refresh 7 дней;
- [ ] rotation;
- [ ] reuse detection;
- [ ] absolute expiry;
- [ ] idle timeout;
- [ ] device binding;
- [ ] revoke list;
- [ ] concurrent session list.

### Защита

- [ ] HTTPS/HSTS;
- [ ] CSP;
- [ ] CSRF token + Origin check;
- [ ] rate limit;
- [ ] audit;
- [ ] anomaly detection;
- [ ] step-up WebAuthn.

### Gateway

- [ ] strip incoming `X-AuthLayer-*`;
- [ ] app only localhost/private;
- [ ] mTLS proxy→app;
- [ ] firewall;
- [ ] health checks;
- [ ] fail closed.

---

## 11. Тесты

| Тест | Ожидание |
|---|---|
| Украсть куку, отправить без DPoP | 401 |
| Украсть куку + DPoP другого ключа | 401 |
| Повторить DPoP proof | 401 (jti) |
| Изменить `htu`/`htm` | 401 |
| Истёк access | 401, refresh работает |
| Повторно использовать refresh | вся family отозвана |
| Отозвать устройство | все сессии 401 |
| 7 дней прошло | re-auth |
| XSS | HttpOnly кука не читается; CSP |
| CSRF | SameSite + token блокируют |
| Session fixation | ID меняется при login |
| Gateway header spoof | заголовок срезан |
| DBSC без ключа | refresh не проходит |
| JWE с неверным tag | 401 |
| JWE с истёкшим `exp` | 401 |

---

## 12. Код: Express middleware (эскиз)

```ts
import type { Request, Response, NextFunction } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';

export function sessionMiddleware(store: SessionStore) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const raw = req.cookies['__Host-al_session'];
    if (!raw) return res.status(401).json({ error: 'unauthenticated' });

    const idHash = createHash('sha256').update(raw).digest();
    const session = await store.get(idHash);
    if (!session) return res.status(401).json({ error: 'unauthenticated' });

    if (session.revokedAt || Date.now() > session.expiresAt) {
      await store.revoke(idHash);
      res.clearCookie('__Host-al_session');
      return res.status(401).json({ error: 'unauthenticated' });
    }

    const device = await store.getDevice(session.deviceId);
    if (!device || device.status !== 'active') {
      return res.status(401).json({ error: 'device_revoked' });
    }

    if (!(await verifyBinding(req, session))) {
      return res.status(401).json({ error: 'invalid_binding' });
    }

    req.user = await store.getUser(session.accountId);
    req.session = session;
    next();
  };
}
```

`verifyBinding`:

```ts
async function verifyBinding(req: Request, session: Session) {
  if (session.bindingType === 'dpop') {
    const proof = req.header('DPoP');
    if (!proof) return false;
    return verifyDpop(proof, {
      htm: req.method,
      htu: absoluteUrl(req),
      accessToken: bearer(req),
      jkt: session.bindingJkt,
    });
  }
  if (session.bindingType === 'dbsc') {
    return verifyDbsc(req, session);
  }
  if (session.bindingType === 'mtls') {
    return verifyMtls(req, session);
  }
  return false; // fail closed
}
```

---

## 13. Код: Caddy forward-auth (эскиз)

```caddyfile
example.com {
    handle /_authlayer/* {
        reverse_proxy authlayerd:8080
    }

    handle {
        forward_auth authlayerd:8080 {
            uri /verify
            copy_headers X-AuthLayer-User X-AuthLayer-DeviceId X-AuthLayer-SessionId
        }
        reverse_proxy app:3000
    }
}
```

`authlayerd /verify`:

```text
1. читает куку;
2. проверяет сессию;
3. проверяет device binding;
4. возвращает 200 + X-AuthLayer-* или 401.
```

Приложение не должно быть доступно напрямую.

---

## 14. Что остаётся уязвимым

- **Malware на устройстве**: если ключ в TPM, извлечь сложно; но malware может действовать от имени пользователя, пока сессия жива. Решение: step-up, короткие сессии, EDR.
- **XSS**: HttpOnly защищает куку, но XSS может делать запросы. CSP, санитизация, Trusted Types.
- **Злоупотребление расширением/прокси**: supply chain, permissions, code review.
- **Скомпрометированный gateway**: он видит заголовки; mTLS, least privilege, immutable image.
- **Скомпрометированный целевой сайт**: пароль утекает; passkeys/ротация.
- **Сброс пароля по email**: не решается куками; отдельный email/passkey.
- **Пользователь подтверждает вредоносный запрос**: контекст, number matching, rate limit.

---

## 15. Итог

1. **Не выдавать ключ расшифровки клиенту.** Это превращает сессию в bearer-токен и создаёт новую точку утечки.
2. **Шифровать куку можно**, но это только конфиденциальность/integrity. Для 7 дней — opaque server-side session.
3. **Защита от кражи — device binding**: DPoP (API/CLI), DBSC (браузер), mTLS (enterprise).
4. **7 дней — refresh, не access.** Rotation + reuse detection + revoke.
5. **Проверка права — это подпись устройства**, а не выдача ключа.
6. **Если браузер не поддерживает DBSC** — fallback: короткий TTL + WebAuthn step-up + risk; не обещать невозможное.
