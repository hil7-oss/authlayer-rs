#!/usr/bin/env node
// AuthLayer HTTP smoke test.
//
// Dependency-free: uses only Node's global fetch. No npm install required.
//
// Usage:
//   node scripts/smoke.mjs
//   BASE_URL=http://localhost:8080 node scripts/smoke.mjs
//
// Exit codes:
//   0 = all executed checks passed (skips are allowed)
//   1 = a check failed, the server was unreachable, or a request timed out
//
// The script does not print email bodies, OTP codes, session tokens, or admin tokens.

const BASE = process.env.BASE_URL || 'http://localhost:8080';
const TIMEOUT_MS =
  Number(process.env.SMOKE_TIMEOUT_MS) > 0 ? Number(process.env.SMOKE_TIMEOUT_MS) : 10_000;

// Unique per run so OTP state and the per-email rate limit never collide.
const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
const email = `smoke-${runId}@example.test`;

let passed = 0;
let failed = 0;
let skipped = 0;
let otpCode = null;
const startedAt = Date.now();

// Thrown after a failed check so the script stops at the first failure.
class SmokeStop extends Error {}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function assertStatus(response, expected, label = 'status') {
  const allowed = Array.isArray(expected) ? expected : [expected];
  if (!allowed.includes(response.status)) {
    const apiError = response.json?.error ? `, error=${response.json.error}` : '';
    throw new Error(
      `${label}: expected HTTP ${allowed.join(' or ')}, got ${response.status}${apiError}`,
    );
  }
}

async function request(path, options = {}) {
  const url = `${BASE.replace(/\/+$/, '')}${path}`;
  const headers = {
    'user-agent': 'authlayer-smoke/1.0',
    ...(options.body !== undefined ? { 'content-type': 'application/json' } : {}),
    ...options.headers,
  };

  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    const reason =
      err?.cause?.code || err?.cause?.message || err?.name || err?.message || String(err);
    throw new Error(`request to ${url} failed (${reason}). Is the server running?`);
  }

  let text;
  try {
    text = await response.text();
  } catch (err) {
    throw new Error(`could not read response body from ${url}: ${err?.message || err}`);
  }

  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      // Some endpoints return HTML; callers that need JSON check for null.
    }
  }

  return { status: response.status, ok: response.ok, headers: response.headers, text, json };
}

function postJson(path, body) {
  return request(path, { method: 'POST', body: JSON.stringify(body) });
}

function setCookieHeaders(response) {
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie();
  }
  const raw = response.headers.get('set-cookie');
  return raw ? [raw] : [];
}

function findSetCookie(response, name) {
  const prefix = `${name}=`;
  for (const header of setCookieHeaders(response)) {
    if (header.trim().toLowerCase().startsWith(prefix.toLowerCase())) return header;
  }
  return null;
}

function extractOtp(body) {
  if (typeof body !== 'string') return null;
  const labeled = body.match(/(?:one-time code is|code is)\s*:?\s*(\d{6})\b/i);
  if (labeled) return labeled[1];
  const anySixDigits = body.match(/\b(\d{6})\b/);
  return anySixDigits ? anySixDigits[1] : null;
}

async function check(name, fn) {
  try {
    const result = await fn();
    if (result && typeof result === 'object' && typeof result.skip === 'string') {
      skipped += 1;
      console.log(`SKIP  ${name} - ${result.skip}`);
      return;
    }
    passed += 1;
    console.log(`PASS  ${name}${result ? ` - ${result}` : ''}`);
  } catch (err) {
    failed += 1;
    const message = err instanceof Error ? err.message : String(err);
    console.error(`FAIL  ${name}`);
    console.error(`      ${message.split('\n').join('\n      ')}`);
    throw new SmokeStop();
  }
}

function skip(name, reason) {
  skipped += 1;
  console.log(`SKIP  ${name} - ${reason}`);
}

function printSummary() {
  const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log('');
  console.log('----------------------------------------');
  console.log(`Summary: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  console.log(`Base URL: ${BASE}`);
  console.log(`Duration: ${seconds}s`);
  if (skipped > 0) {
    console.log('Skipped checks are optional or depend on DEV_MODE/ADMIN_TOKEN.');
  }
}

async function main() {
  console.log('AuthLayer smoke test');
  console.log(`Base URL: ${BASE}`);
  console.log('');

  // Reuse this response for the health check, and detect a dead server early.
  let health;
  try {
    health = await request('/healthz');
  } catch (err) {
    failed += 1;
    console.error('FAIL  Server reachable');
    console.error(`      ${err instanceof Error ? err.message : String(err)}`);
    console.error('      Start the server first; see scripts/README.md.');
    printSummary();
    return 1;
  }

  try {
    await check('GET /healthz (DB-backed) returns 200 with ok:true', async () => {
      assertStatus(health, 200);
      assertEqual(health.json?.ok, true, 'body.ok');
      const devMode =
        typeof health.json?.dev_mode === 'boolean' ? `, dev_mode=${health.json.dev_mode}` : '';
      return `HTTP 200, ok=true (DB probe passed)${devMode}`;
    });

    await check('GET / returns 200 and contains AuthLayer', async () => {
      const res = await request('/');
      assertStatus(res, 200);
      assert(res.text.includes('AuthLayer'), 'response body does not contain "AuthLayer"');
      return 'HTTP 200, marker found';
    });

    await check('GET /style.css returns 200 and is non-empty', async () => {
      const res = await request('/style.css');
      assertStatus(res, 200);
      assert(res.text.length > 0, 'response body is empty');
      return `HTTP 200, ${res.text.length} bytes`;
    });

    await check('GET /app.js returns 200 and is non-empty', async () => {
      const res = await request('/app.js');
      assertStatus(res, 200);
      assert(res.text.length > 0, 'response body is empty');
      return `HTTP 200, ${res.text.length} bytes`;
    });

    await check('GET /api/me without a cookie is anonymous', async () => {
      const res = await request('/api/me');
      assertStatus(res, 200);
      assertEqual(res.json?.authenticated, false, 'body.authenticated');
      return 'HTTP 200, authenticated=false';
    });

    await check('Cache-Control: no-store is present on /healthz, /api/me, / and /app.js', async () => {
      const paths = ['/healthz', '/api/me', '/', '/app.js'];
      for (const path of paths) {
        const res = await request(path);
        assertStatus(res, 200);
        const cacheControl = res.headers.get('cache-control') || '';
        assert(
          cacheControl.toLowerCase().includes('no-store'),
          `${path}: expected Cache-Control containing "no-store", got ${
            cacheControl ? `"${cacheControl}"` : 'no header'
          }`,
        );
      }
      return `no-store on all ${paths.length} endpoints`;
    });

    await check('POST /api/auth/start rejects an invalid email', async () => {
      const res = await postJson('/api/auth/start', { email: 'not-an-email' });
      assertStatus(res, 400);
      return `HTTP 400${res.json?.error ? `, error=${res.json.error}` : ''}`;
    });

    await check('POST /api/auth/start accepts a unique email', async () => {
      const res = await postJson('/api/auth/start', { email });
      assertStatus(res, 200);
      assertEqual(res.json?.flow, 'code', 'body.flow');
      return 'HTTP 200, flow=code';
    });

    await check('GET /api/dev/outbox exposes the OTP', async () => {
      const res = await request('/api/dev/outbox');
      if (res.status === 404) {
        return { skip: 'HTTP 404 - DEV_MODE is off; OTP verification checks will be skipped' };
      }
      assertStatus(res, 200);
      assert(Array.isArray(res.json?.messages), 'body.messages is not an array');

      const messages = res.json.messages;
      const matching = messages
        .filter((message) => String(message?.to || '').toLowerCase() === email)
        .sort((a, b) =>
          String(b?.created_at || '').localeCompare(String(a?.created_at || '')),
        );

      assert(matching.length > 0, 'no outbox message found for the smoke-test address');
      otpCode = extractOtp(matching[0]?.body);
      assert(otpCode, 'no 6-digit code found in the outbox message body');
      return `HTTP 200, ${messages.length} message(s), 6-digit code found`;
    });

    await check('POST /api/auth/verify-code rejects a wrong code', async () => {
      if (!otpCode) return { skip: 'no OTP available (dev outbox disabled)' };
      const wrongCode = otpCode === '000000' ? '000001' : '000000';
      const res = await postJson('/api/auth/verify-code', { email, code: wrongCode });
      assertStatus(res, 400);
      return `HTTP 400${res.json?.error ? `, error=${res.json.error}` : ''}`;
    });

    await check('POST /api/auth/verify-code rejects a non-existent user', async () => {
      // Separate address, so this cannot consume the real OTP created above.
      const missingEmail = `missing-${runId}@example.test`;
      const res = await postJson('/api/auth/verify-code', {
        email: missingEmail,
        code: '123456',
      });
      assertStatus(res, 400);
      return `HTTP 400${res.json?.error ? `, error=${res.json.error}` : ''}`;
    });

    await check('POST /api/auth/verify-code accepts the real code', async () => {
      if (!otpCode) return { skip: 'no OTP available (dev outbox disabled)' };
      const res = await postJson('/api/auth/verify-code', { email, code: otpCode });
      assertStatus(res, 200);
      assertEqual(res.json?.flow, 'register_passkey', 'body.flow');
      assert(
        typeof res.json?.challenge_id === 'string' && res.json.challenge_id.length > 0,
        'body.challenge_id is missing',
      );
      assert(res.json?.options && typeof res.json.options === 'object', 'body.options is missing');
      return 'HTTP 200, flow=register_passkey (WebAuthn ceremony not automated)';
    });

    await check('GET /api/sessions without a cookie returns 401', async () => {
      const res = await request('/api/sessions');
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/auth/stepup/start without a cookie returns 401', async () => {
      const res = await postJson('/api/auth/stepup/start', {});
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/auth/stepup/finish without a cookie returns 401', async () => {
      // Valid structure so the JSON extractor does not reject the request first.
      const res = await postJson('/api/auth/stepup/finish', {
        challenge_id: 'x',
        credential: {},
      });
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/sessions/revoke-all without a cookie returns 401', async () => {
      const res = await request('/api/sessions/revoke-all', { method: 'POST' });
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/passkeys/add/start without a cookie returns 401', async () => {
      const res = await postJson('/api/passkeys/add/start', {});
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/passkeys/add/finish without a cookie returns 401', async () => {
      // The handler has a JSON extractor before the session check, so send a
      // structurally valid body; otherwise Axum rejects it before authentication.
      const res = await postJson('/api/passkeys/add/finish', {
        challenge_id: 'smoke-no-challenge',
        credential: {},
      });
      assertStatus(res, 401);
      return 'HTTP 401';
    });

    await check('POST /api/auth/logout without a cookie does not return 500', async () => {
      const res = await request('/api/auth/logout', { method: 'POST' });
      assertStatus(res, [200, 401]);
      return `HTTP ${res.status}, not 500`;
    });

    const adminTokenSet = Boolean(process.env.ADMIN_TOKEN);

    await check('GET /admin without an admin cookie is denied', async () => {
      const res = await request('/admin', { redirect: 'manual' });
      if (adminTokenSet && res.status === 404) {
        throw new Error(
          'expected a redirect for enabled admin, got 404 - server appears to have no ADMIN_TOKEN configured',
        );
      }
      const allowed = adminTokenSet ? [302, 303, 401, 403] : [302, 303, 401, 403, 404];
      assertStatus(res, allowed);
      if (res.status === 302 || res.status === 303) {
        const location = res.headers.get('location') || '';
        assert(
          location.includes('/admin/login'),
          `redirect location: expected /admin/login, got ${location || '<missing>'}`,
        );
        return `HTTP ${res.status} -> /admin/login`;
      }
      return `HTTP ${res.status}, not 200`;
    });

    if (!adminTokenSet) {
      const reason = 'ADMIN_TOKEN is not set in this process';
      skip('GET /admin/login returns 200 with the login form', reason);
      skip('POST /admin/login rejects a wrong token', reason);
      skip('POST /admin/login accepts the correct token', reason);
      skip('GET /admin with a valid admin cookie returns the admin page', reason);
      skip('POST /admin/logout clears the al_admin cookie', reason);
    } else {
      await check('GET /admin/login returns 200 with the login form', async () => {
        const res = await request('/admin/login', { redirect: 'manual' });
        assertStatus(res, 200);
        assert(res.text.includes('name="token"'), 'login form token field is missing');
        return 'HTTP 200, login form found';
      });

      await check('POST /admin/login rejects a wrong token', async () => {
        const wrongToken = `smoke-wrong-${Date.now()}`;
        const res = await postJson('/admin/login', { token: wrongToken });
        assertStatus(res, 403);
        return 'HTTP 403';
      });

      let adminCookie = null;
      await check('POST /admin/login accepts the correct token', async () => {
        const res = await postJson('/admin/login', { token: process.env.ADMIN_TOKEN });
        assertStatus(res, 200);
        assertEqual(res.json?.ok, true, 'body.ok');
        const setCookie = findSetCookie(res, 'al_admin');
        assert(setCookie, 'Set-Cookie containing al_admin is missing');
        adminCookie = setCookie.split(';', 1)[0].trim();
        assert(adminCookie.startsWith('al_admin='), 'al_admin cookie pair is malformed');
        return 'HTTP 200, ok=true, al_admin cookie set';
      });

      await check('GET /admin with a valid admin cookie returns the admin page', async () => {
        assert(adminCookie, 'no al_admin cookie from login');
        const res = await request('/admin', {
          headers: { cookie: adminCookie },
          redirect: 'manual',
        });
        assertStatus(res, 200);
        assert(res.text.includes('AuthLayer admin'), 'page does not contain "AuthLayer admin"');
        return 'HTTP 200, admin page marker found';
      });

      await check('POST /admin/logout clears the al_admin cookie', async () => {
        assert(adminCookie, 'no al_admin cookie from login');
        const res = await request('/admin/logout', {
          method: 'POST',
          headers: { cookie: adminCookie },
          redirect: 'manual',
        });
        assert(
          res.status >= 200 && res.status < 400,
          `status: expected 2xx/3xx, got ${res.status}`,
        );
        const setCookie = findSetCookie(res, 'al_admin');
        assert(setCookie, 'Set-Cookie clearing al_admin is missing');
        const lower = setCookie.toLowerCase();
        assert(
          lower.includes('max-age=0') ||
            (lower.includes('expires=') && lower.includes('1970')),
          'al_admin Set-Cookie is not marked for clearing',
        );
        return `HTTP ${res.status}, al_admin cleared`;
      });
    }

    await check('GET /api/dev/outbox behavior matches DEV_MODE', async () => {
      const res = await request('/api/dev/outbox');
      const devMode = health.json?.dev_mode;

      if (typeof devMode === 'boolean') {
        if (devMode) {
          assertStatus(res, 200);
          assert(Array.isArray(res.json?.messages), 'body.messages is not an array');
          return `dev_mode=true, HTTP 200 with ${res.json.messages.length} message(s)`;
        }
        assertStatus(res, 404);
        return 'dev_mode=false, HTTP 404';
      }

      // Older health payloads may omit dev_mode; at minimum, enforce gating.
      assertStatus(res, [200, 404]);
      if (res.status === 200) {
        assert(Array.isArray(res.json?.messages), 'body.messages is not an array');
      }
      return `dev_mode unknown, HTTP ${res.status} (gated)`;
    });
  } catch (err) {
    if (!(err instanceof SmokeStop)) {
      failed += 1;
      console.error('FAIL  Unexpected error');
      console.error(`      ${err?.stack || String(err)}`);
    }
  }

  printSummary();
  return failed > 0 ? 1 : 0;
}

process.exitCode = await main();
