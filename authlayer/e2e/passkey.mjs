#!/usr/bin/env node
/*
 * AuthLayer real-browser E2E harness.
 *
 * Uses Chrome (via playwright-core, no browser download) plus the CDP
 * WebAuthn virtual authenticator. No Rust code is built or modified here.
 *
 * Default flow:
 *   1. email form -> OTP from /api/dev/outbox -> create passkey
 *   2. recovery codes -> dashboard
 *   3. logout -> passkey sign-in -> dashboard
 *   4. cookie invariants
 *   5. optional step-up, second passkey, and revoke (SKIP if the UI/API is
 *      mid-security-wave and cannot complete the step-up-dependent action)
 *
 * Exit code: 0 when every non-skipped step passed, 1 otherwise.
 */

import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createWriteStream, existsSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const E2E_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_BASE_URL = 'http://localhost:8080';
const DEFAULT_CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const RUN_ID = `${Date.now()}-${randomBytes(3).toString('hex')}`;
const EMAIL = `e2e-${RUN_ID}@example.test`;
const DB_NAME = `e2e-${process.pid}.db`;
const DB_PATH = join(E2E_DIR, DB_NAME);
const SERVER_LOG_PATH = join(E2E_DIR, `.e2e-server-${process.pid}.log`);
const PASSKEY_ITEM_SELECTOR =
  'section.panel[aria-labelledby="passkeys-heading"] li.list-item';

const ENV = {
  baseUrl: (process.env.E2E_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, ''),
  binary: process.env.E2E_BINARY
    ? resolve(process.cwd(), process.env.E2E_BINARY)
    : join(E2E_DIR, '..', 'target', 'debug', 'authlayer.exe'),
  chromePath: process.env.E2E_CHROME_PATH || DEFAULT_CHROME_PATH,
  rpId: (process.env.E2E_RP_ID || 'localhost').trim(),
  cookieName: (process.env.E2E_COOKIE_NAME || 'al_session').trim(),
  adminToken: process.env.E2E_ADMIN_TOKEN || '',
  startServer: process.env.E2E_START_SERVER === '1',
  headless: !/^(0|false)$/i.test(process.env.E2E_HEADLESS ?? '1'),
  headedFallback: !/^(0|false)$/i.test(process.env.E2E_HEADED_FALLBACK ?? '1'),
  keepArtifacts: process.env.E2E_KEEP_ARTIFACTS === '1',
};

const diagnostics = {
  pageErrors: [],
  consoleErrors: [],
  requestFailures: [],
  serverErrors: [],
  responses: [],
};
const results = [];
const stepUpEvidence = [];
let failures = 0;
let skips = 0;
let serverChild = null;
let serverLogStream = null;
let serverLogTail = '';
let browser = null;
let browserContext = null;
let page = null;
let cdpSession = null;
let authenticatorIds = [];
let headedFallbackUsed = false;
let cleanupPromise = null;

class StepAbort extends Error {}

/* ---------- logging ---------- */

function stamp() {
  return new Date().toISOString().replace('T', ' ');
}

function log(message) {
  console.log(`[${stamp()}] ${message}`);
}

function logDetail(message) {
  for (const line of String(message).split('\n')) {
    console.log(`[${stamp()}]   ${line}`);
  }
}

function oneLine(value) {
  return String(value).replace(/\s+/g, ' ').trim();
}

function delay(ms) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, ms));
}

function settleWithTimeout(promise, ms, fallback) {
  return new Promise((resolveSettle) => {
    const timer = setTimeout(() => resolveSettle(fallback), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolveSettle(value);
      },
      () => {
        clearTimeout(timer);
        resolveSettle(fallback);
      },
    );
  });
}

function waitForChildExit(child, ms) {
  if (!child || child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolveExit) => {
    const timer = setTimeout(() => resolveExit(false), ms);
    child.once('exit', () => {
      clearTimeout(timer);
      resolveExit(true);
    });
  });
}

/* ---------- config ---------- */

function loadConfig() {
  let base;
  try {
    base = new URL(ENV.baseUrl);
  } catch {
    throw new Error(`E2E_BASE_URL is not a valid URL: ${ENV.baseUrl}`);
  }
  if (base.protocol !== 'http:' && base.protocol !== 'https:') {
    throw new Error('E2E_BASE_URL must use http:// or https://');
  }
  if (base.pathname !== '/' || base.search || base.hash || base.username || base.password) {
    throw new Error('E2E_BASE_URL must be a bare origin, for example http://localhost:8080');
  }
  const host = base.hostname.toLowerCase();
  const loopback = host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  const rpId = ENV.rpId.toLowerCase();
  if (host !== rpId && !host.endsWith(`.${rpId}`)) {
    throw new Error(
      `RP_ID ${JSON.stringify(ENV.rpId)} is not valid for ${base.origin}. ` +
        'Use a hostname equal to RP_ID (localhost by default), or set E2E_RP_ID.',
    );
  }
  if (base.protocol === 'http:' && !loopback) {
    throw new Error(
      'WebAuthn needs a secure context. Serve E2E_BASE_URL over HTTPS, or use localhost/127.0.0.1.',
    );
  }
  if (ENV.startServer && !loopback) {
    throw new Error(
      'E2E_START_SERVER=1 requires a loopback E2E_BASE_URL because the server runs with DEV_MODE=true.',
    );
  }
  if (ENV.startServer && !existsSync(ENV.binary)) {
    throw new Error(
      `AuthLayer binary not found at ${ENV.binary}. Build it first or set E2E_BINARY.`,
    );
  }
  if (ENV.adminToken && ENV.adminToken.length < 32) {
    throw new Error('E2E_ADMIN_TOKEN must be at least 32 characters when set.');
  }

  const port = base.port || (base.protocol === 'https:' ? '443' : '80');
  const healthUrl = new URL('/healthz', base.origin);
  if (healthUrl.hostname === 'localhost') {
    // The spawned server binds IPv4 only. Avoid localhost choosing ::1 first.
    healthUrl.hostname = '127.0.0.1';
  }

  return {
    baseUrl: base.origin,
    origin: base.origin,
    host,
    protocol: base.protocol,
    healthUrl: healthUrl.toString(),
    port,
    bindAddr: `127.0.0.1:${port}`,
    rpId: ENV.rpId,
    cookieName: ENV.cookieName,
    binary: ENV.binary,
    chromePath: ENV.chromePath,
    adminToken: ENV.adminToken,
    startServer: ENV.startServer,
    headless: ENV.headless,
    headedFallback: ENV.headedFallback,
    keepArtifacts: ENV.keepArtifacts,
    email: EMAIL,
    databaseUrl: `sqlite://${DB_NAME}?mode=rwc`,
    databasePath: DB_PATH,
  };
}

/* ---------- server lifecycle ---------- */

async function probeHealth(url, timeoutMs = 1500) {
  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await response.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
    return {
      ok: response.ok && Boolean(data && data.ok === true),
      status: response.status,
      detail: data ? JSON.stringify(data) : text.slice(0, 300),
      error: '',
    };
  } catch (error) {
    return { ok: false, status: 0, detail: '', error: error.message };
  }
}

async function waitForHealth(cfg, maxMs) {
  const deadline = Date.now() + maxMs;
  let last = null;
  while (Date.now() < deadline) {
    if (serverChild && serverChild.exitCode !== null) {
      throw new Error(
        `AuthLayer server exited early with code ${serverChild.exitCode}.\n${serverLogTail.slice(-4000)}`,
      );
    }
    last = await probeHealth(cfg.healthUrl);
    if (last.ok) {
      log(`Server is healthy at ${cfg.healthUrl}`);
      return;
    }
    await delay(400);
  }
  const detail = last
    ? last.error || `HTTP ${last.status} ${last.detail}`.trim()
    : 'no response';
  throw new Error(
    `Server did not become healthy at ${cfg.healthUrl} within ${Math.round(maxMs / 1000)}s (${detail}).` +
      (serverLogTail ? `\nLast server output:\n${serverLogTail.slice(-4000)}` : ''),
  );
}

async function startServer(cfg) {
  const env = {
    ...process.env,
    APP_URL: cfg.origin,
    RP_ID: cfg.rpId,
    BIND_ADDR: cfg.bindAddr,
    DATABASE_URL: cfg.databaseUrl,
    DEV_MODE: 'true',
    EMAIL_PROVIDER: 'outbox',
    OTP_SECRET: randomBytes(32).toString('hex'),
    COOKIE_SECURE: 'false',
    COOKIE_NAME: cfg.cookieName,
  };
  delete env.ADMIN_TOKEN;
  if (cfg.adminToken) env.ADMIN_TOKEN = cfg.adminToken;

  serverLogStream = createWriteStream(SERVER_LOG_PATH, { flags: 'w' });
  serverLogTail = '';
  serverChild = spawn(cfg.binary, [], {
    cwd: E2E_DIR,
    env,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const collect = (chunk) => {
    serverLogTail = (serverLogTail + chunk.toString()).slice(-12000);
  };
  serverChild.stdout.on('data', collect);
  serverChild.stderr.on('data', collect);
  serverChild.stdout.pipe(serverLogStream, { end: false });
  serverChild.stderr.pipe(serverLogStream, { end: false });
  serverChild.on('error', (error) => {
    serverLogTail += `\n[spawn error] ${error.stack || error.message}`;
  });

  log(`Spawned ${cfg.binary} (pid ${serverChild.pid}) with ${cfg.databaseUrl}`);
  await waitForHealth(cfg, 20_000);
}

async function ensureExternalServer(cfg) {
  const health = await probeHealth(cfg.healthUrl, 2500);
  if (!health.ok) {
    const detail = health.error || `HTTP ${health.status} ${health.detail}`.trim();
    throw new Error(
      `No healthy AuthLayer server at ${cfg.healthUrl} (${detail}). ` +
        'Start it first, or run with E2E_START_SERVER=1.',
    );
  }
  log(`Using already-running server at ${cfg.healthUrl}`);
}

async function removeDatabaseFiles() {
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    await rm(`${DB_PATH}${suffix}`, { force: true }).catch(() => {});
  }
}

async function stopServer() {
  const child = serverChild;
  serverChild = null;
  if (child && child.exitCode === null) {
    try {
      child.kill();
    } catch {
      /* already gone */
    }
    const exited = await waitForChildExit(child, 5000);
    if (!exited && child.pid) {
      log(`Server pid ${child.pid} did not exit; forcing taskkill.`);
      if (process.platform === 'win32') {
        spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
          windowsHide: true,
          stdio: 'ignore',
        });
      } else {
        try {
          child.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }
      await waitForChildExit(child, 2000);
    }
  }

  if (serverLogStream) {
    const stream = serverLogStream;
    serverLogStream = null;
    await new Promise((resolveEnd) => stream.end(resolveEnd)).catch(() => {});
  }
  await removeDatabaseFiles();
}

async function doCleanup() {
  if (browser) {
    const current = browser;
    browser = null;
    try {
      await settleWithTimeout(current.close(), 10_000, undefined);
    } catch (error) {
      log(`WARN browser close failed: ${oneLine(error.message)}`);
    }
  }
  browserContext = null;
  page = null;
  cdpSession = null;
  authenticatorIds = [];
  await stopServer();

  if (!ENV.keepArtifacts && failures === 0) {
    await rm(SERVER_LOG_PATH, { force: true }).catch(() => {});
  } else if (existsSync(SERVER_LOG_PATH)) {
    log(`Server log kept at ${SERVER_LOG_PATH}`);
  }
}

function cleanup() {
  if (!cleanupPromise) cleanupPromise = doCleanup();
  return cleanupPromise;
}

/* ---------- browser setup ---------- */

async function addVirtualAuthenticator(session, transport) {
  const options = {
    protocol: 'ctap2',
    ctap2Version: 'ctap2_1',
    transport,
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  };
  try {
    const result = await session.send('WebAuthn.addVirtualAuthenticator', { options });
    if (!result || typeof result.authenticatorId !== 'string' || !result.authenticatorId) {
      throw new Error('CDP did not return an authenticatorId');
    }
    return result.authenticatorId;
  } catch (error) {
    // Older Chrome builds may not know ctap2_1. Retry with Chrome's default
    // CTAP2 version so the harness still works on slightly older browsers.
    if (!/ctap2_1|ctap2Version/i.test(String(error.message))) throw error;
    log('WARN this Chrome does not accept ctap2Version=ctap2_1; retrying with the default.');
    const fallbackOptions = { ...options };
    delete fallbackOptions.ctap2Version;
    const result = await session.send('WebAuthn.addVirtualAuthenticator', {
      options: fallbackOptions,
    });
    if (!result || typeof result.authenticatorId !== 'string' || !result.authenticatorId) {
      throw new Error('CDP did not return an authenticatorId');
    }
    return result.authenticatorId;
  }
}

async function launchBrowserAttempt(cfg, headless) {
  let launched = null;
  try {
    launched = await chromium.launch({
      executablePath: cfg.chromePath,
      headless,
      timeout: 30_000,
      args: ['--no-first-run', '--no-default-browser-check'],
    });
    const context = await launched.newContext({
      baseURL: cfg.origin,
      viewport: { width: 1280, height: 900 },
      locale: 'en-US',
    });
    const newPage = await context.newPage();
    newPage.setDefaultTimeout(15_000);
    newPage.setDefaultNavigationTimeout(25_000);

    const session = await context.newCDPSession(newPage);
    await session.send('WebAuthn.enable', { enableUI: false });
    const authenticatorId = await addVirtualAuthenticator(session, 'internal');

    return {
      browser: launched,
      context,
      page: newPage,
      cdp: session,
      authenticatorId,
    };
  } catch (error) {
    if (launched) await launched.close().catch(() => {});
    throw error;
  }
}

async function setupBrowser(cfg) {
  if (!existsSync(cfg.chromePath)) {
    throw new Error(
      `Chrome not found at ${cfg.chromePath}. Install Chrome or set E2E_CHROME_PATH.`,
    );
  }

  try {
    const setup = await launchBrowserAttempt(cfg, cfg.headless);
    log(`Chrome launched (headless: ${cfg.headless}) with a virtual authenticator.`);
    return setup;
  } catch (headlessError) {
    if (!cfg.headless || !cfg.headedFallback) throw headlessError;
    log(`WARN headless Chrome + WebAuthn setup failed: ${oneLine(headlessError.message)}`);
    log('Falling back to headless: false (E2E_HEADED_FALLBACK=1).');
    try {
      const setup = await launchBrowserAttempt(cfg, false);
      headedFallbackUsed = true;
      log('Chrome launched headed with a virtual authenticator (fallback).');
      return setup;
    } catch (headedError) {
      throw new Error(
        `Headless browser setup failed: ${oneLine(headlessError.message)}. ` +
          `Headed fallback also failed: ${oneLine(headedError.message)}`,
      );
    }
  }
}

/* ---------- diagnostics ---------- */

function attachDiagnostics(targetPage) {
  targetPage.on('pageerror', (error) => {
    diagnostics.pageErrors.push({
      text: error.stack || String(error),
      url: targetPage.url(),
    });
  });
  targetPage.on('console', (message) => {
    if (message.type() !== 'error') return;
    const location = message.location();
    diagnostics.consoleErrors.push({
      text: message.text(),
      url: location && location.url ? location.url : '',
      line: location && Number.isFinite(location.lineNumber) ? location.lineNumber : null,
      tolerated: false,
    });
  });
  targetPage.on('requestfailed', (request) => {
    const failure = request.failure();
    diagnostics.requestFailures.push({
      method: request.method(),
      url: request.url(),
      error: failure && failure.errorText ? failure.errorText : 'unknown',
    });
  });
  targetPage.on('response', (response) => {
    diagnostics.responses.push({
      method: response.request().method(),
      url: response.url(),
      status: response.status(),
      at: Date.now(),
    });
    if (response.status() >= 500) {
      diagnostics.serverErrors.push({
        status: response.status(),
        url: response.url(),
      });
    }
  });
}

/* ---------- step runner ---------- */

async function step(name, fn, options = {}) {
  const started = Date.now();
  const consoleMark = diagnostics.consoleErrors.length;
  log(`---- ${name}`);
  try {
    await fn();
    const ms = Date.now() - started;
    results.push({ name, status: 'PASS', ms });
    log(`PASS ${name} (${ms}ms)`);
    return true;
  } catch (error) {
    const ms = Date.now() - started;
    if (options.optional) {
      // A skipped optional step may legitimately produce a failed network
      // request in the browser console (e.g. HTTP 403 step-up required).
      // Give the console event a moment to arrive, then tolerate only errors
      // observed while this optional step ran.
      await delay(150);
      for (let index = consoleMark; index < diagnostics.consoleErrors.length; index += 1) {
        diagnostics.consoleErrors[index].tolerated = true;
      }
      skips += 1;
      results.push({ name, status: 'SKIP', ms, detail: oneLine(error.message) });
      log(`SKIP ${name} (${ms}ms): ${oneLine(error.message)}`);
      return false;
    }
    failures += 1;
    results.push({ name, status: 'FAIL', ms, detail: oneLine(error.message) });
    log(`FAIL ${name} (${ms}ms): ${oneLine(error.message)}`);
    if (error.stack) logDetail(error.stack);
    throw new StepAbort(name);
  }
}

function skipStep(name, reason) {
  skips += 1;
  results.push({ name, status: 'SKIP', ms: 0, detail: oneLine(reason) });
  log(`SKIP ${name}: ${oneLine(reason)}`);
}

/* ---------- page helpers ---------- */

async function readStat(targetPage, label) {
  const stat = targetPage.locator('.stat').filter({ hasText: label }).first();
  const value = await stat.locator('.stat-value').innerText();
  return value.trim();
}

async function waitForAnyHeading(targetPage, names, timeout = 25_000) {
  await targetPage.waitForFunction(
    (wanted) => {
      const title = document.querySelector('.screen-title');
      if (!title) return false;
      const text = title.textContent || '';
      return wanted.some((name) => text.includes(name));
    },
    names,
    { timeout },
  );
}

async function readOtpFromOutbox(targetPage, email) {
  let lastDetail = 'no attempt made';
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const raw = await targetPage.evaluate(async () => {
      const response = await fetch('/api/dev/outbox', {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      return { status: response.status, ok: response.ok, text: await response.text() };
    });

    if (!raw.ok) {
      lastDetail = `outbox HTTP ${raw.status}: ${raw.text.slice(0, 200)}`;
    } else {
      let data = null;
      try {
        data = JSON.parse(raw.text);
      } catch {
        lastDetail = 'outbox returned invalid JSON';
      }
      if (data) {
        const messages = Array.isArray(data.messages) ? data.messages : [];
        const message = messages.find(
          (item) =>
            item &&
            typeof item.to === 'string' &&
            item.to.toLowerCase() === email.toLowerCase(),
        );
        if (message) {
          const match = /\b(\d{6})\b/.exec(String(message.body || ''));
          if (match) return match[1];
          lastDetail = 'message found but it contained no 6-digit code';
        } else {
          lastDetail = `no message for ${email} yet (${messages.length} messages in outbox)`;
        }
      }
    }
    await targetPage.waitForTimeout(300);
  }
  throw new Error(`Could not read the OTP from /api/dev/outbox: ${lastDetail}`);
}

async function getCookie(cfg, name) {
  const cookies = await browserContext.cookies(cfg.origin);
  return cookies.find((cookie) => cookie.name === name) || null;
}

async function getSessionCookie(cfg) {
  return getCookie(cfg, cfg.cookieName);
}

/*
 * The server binds each WebAuthn ceremony to an HttpOnly al_ceremony cookie.
 * Log its presence and flags without making the E2E result depend on timing:
 * the cookie may already be cleared by the time a step inspects it. The flow
 * itself (same-origin navigator.credentials calls) proves Strict cookies work.
 */
async function logCeremonyCookie(cfg, label) {
  const cookie = await getCookie(cfg, 'al_ceremony');
  if (!cookie) {
    log(`${label}: al_ceremony cookie absent (not set yet or already cleared).`);
    return null;
  }
  const sameSite = String(cookie.sameSite || '');
  const warnings = [];
  if (cookie.httpOnly !== true) warnings.push('not HttpOnly');
  if (sameSite.toLowerCase() !== 'strict') {
    warnings.push(`SameSite=${sameSite || '(none)'} (expected Strict)`);
  }
  if (cookie.path !== '/') warnings.push(`Path=${JSON.stringify(cookie.path)}`);
  if (cfg.protocol === 'http:' && cookie.secure === true) {
    warnings.push('Secure=true over local HTTP');
  }
  if (warnings.length > 0) {
    log(`WARN ${label}: al_ceremony present but ${warnings.join('; ')}.`);
  } else {
    log(
      `${label}: al_ceremony present HttpOnly=true SameSite=${sameSite} ` +
        `Path=${cookie.path} Secure=${cookie.secure}.`,
    );
  }
  return cookie;
}

function assertSessionCookie(cookie, cfg, label) {
  if (!cookie) throw new Error(`${label}: ${cfg.cookieName} cookie is missing`);
  if (!cookie.value) throw new Error(`${label}: ${cfg.cookieName} cookie is empty`);
  if (cookie.httpOnly !== true) throw new Error(`${label}: session cookie is not HttpOnly`);
  if (String(cookie.sameSite || '').toLowerCase() !== 'strict') {
    throw new Error(`${label}: SameSite is ${JSON.stringify(cookie.sameSite)}, expected Strict`);
  }
  if (cookie.path !== '/') {
    throw new Error(`${label}: cookie path is ${JSON.stringify(cookie.path)}, expected /`);
  }
  if (cfg.protocol === 'http:' && cookie.secure === true) {
    throw new Error(`${label}: Secure=true cookie cannot be set over local HTTP`);
  }
  return cookie;
}

/* ---------- visible step-up helpers ---------- */

const CREDENTIAL_GATE_STEP_UP = 'StepUp';
const CREDENTIAL_GATE_CREATE = 'Create';

/*
 * Holds navigator.credentials.get/create at a gate before it reaches the
 * virtual authenticator. The UI has already shown #stepup-status by the time
 * get() is called, so the panel can be asserted without altering authenticator
 * state. Releasing the gate runs the real WebAuthn call.
 */
async function installCredentialGate(targetPage, methodName, gateKey) {
  const installed = await targetPage.evaluate(
    ({ methodName, gateKey }) => {
      const container = navigator.credentials;
      if (!container || typeof container[methodName] !== 'function') return false;
      const gateName = `__e2e${gateKey}Gate`;
      const restoreName = `__e2eRestore${gateKey}Gate`;
      if (window[restoreName]) {
        try {
          window[restoreName]();
        } catch {
          /* ignore */
        }
      }
      const original = container[methodName].bind(container);
      let releaseGate;
      const gate = {
        entered: false,
        released: false,
        release: () => {
          if (gate.released) return;
          gate.released = true;
          releaseGate();
        },
      };
      const wait = new Promise((resolve) => {
        releaseGate = resolve;
      });
      const wrapped = async function (...args) {
        gate.entered = true;
        await wait;
        return original(...args);
      };
      try {
        Object.defineProperty(container, methodName, {
          configurable: true,
          writable: true,
          value: wrapped,
        });
      } catch {
        return false;
      }
      window[gateName] = gate;
      window[restoreName] = () => {
        try {
          Object.defineProperty(container, methodName, {
            configurable: true,
            writable: true,
            value: original,
          });
        } catch {
          /* ignore */
        }
        delete window[gateName];
        delete window[restoreName];
      };
      return true;
    },
    { methodName, gateKey },
  );
  if (!installed) {
    throw new Error(`could not install the navigator.credentials.${methodName} gate`);
  }
}

async function readCredentialGate(targetPage, gateKey) {
  return targetPage.evaluate((key) => {
    const gate = window[`__e2e${key}Gate`];
    return gate
      ? { entered: Boolean(gate.entered), released: Boolean(gate.released) }
      : null;
  }, gateKey);
}

async function waitForCredentialGateEntered(targetPage, gateKey, timeout = 5000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const gate = await readCredentialGate(targetPage, gateKey);
    if (gate && gate.entered) return gate;
    await delay(25);
  }
  const gate = await readCredentialGate(targetPage, gateKey);
  throw new Error(
    gate
      ? `visible step-up panel appeared but navigator.credentials.${gateKey} was not called`
      : `${gateKey} gate was lost before navigator.credentials.${gateKey} was called`,
  );
}

async function releaseCredentialGate(targetPage, gateKey) {
  await targetPage.evaluate((key) => {
    const gate = window[`__e2e${key}Gate`];
    if (gate) gate.release();
  }, gateKey);
}

async function restoreCredentialGate(targetPage, gateKey) {
  await targetPage
    .evaluate((key) => {
      const restore = window[`__e2eRestore${key}Gate`];
      if (restore) restore();
    }, gateKey)
    .catch(() => {});
}

function installStepUpGate(targetPage) {
  return installCredentialGate(targetPage, 'get', CREDENTIAL_GATE_STEP_UP);
}

function waitForStepUpGateEntered(targetPage, timeout) {
  return waitForCredentialGateEntered(targetPage, CREDENTIAL_GATE_STEP_UP, timeout);
}

function releaseStepUpGate(targetPage) {
  return releaseCredentialGate(targetPage, CREDENTIAL_GATE_STEP_UP);
}

function restoreStepUpGate(targetPage) {
  return restoreCredentialGate(targetPage, CREDENTIAL_GATE_STEP_UP);
}

function installCreateGate(targetPage) {
  return installCredentialGate(targetPage, 'create', CREDENTIAL_GATE_CREATE);
}

function waitForCreateGateEntered(targetPage, timeout) {
  return waitForCredentialGateEntered(targetPage, CREDENTIAL_GATE_CREATE, timeout);
}

function releaseCreateGate(targetPage) {
  return releaseCredentialGate(targetPage, CREDENTIAL_GATE_CREATE);
}

function restoreCreateGate(targetPage) {
  return restoreCredentialGate(targetPage, CREDENTIAL_GATE_CREATE);
}

async function removeVirtualAuthenticator(authenticatorId) {
  if (!authenticatorId) return;
  try {
    await cdpSession.send('WebAuthn.removeVirtualAuthenticator', {
      authenticatorId,
    });
  } catch (error) {
    log(`WARN could not remove virtual authenticator ${authenticatorId}: ${oneLine(error.message)}`);
  }
  authenticatorIds = authenticatorIds.filter((id) => id !== authenticatorId);
}

/*
 * Records every hidden/visible transition of the global #stepup-status panel,
 * including very short flashes. This is the evidence that the visible UI
 * step-up flow ran, even if the virtual authenticator completes instantly.
 */
async function installStepUpProbe(targetPage) {
  const installed = await targetPage.evaluate(() => {
    const panel = document.getElementById('stepup-status');
    if (!panel) return false;
    if (window.__e2eStepUpObserver) {
      try {
        window.__e2eStepUpObserver.disconnect();
      } catch {
        /* ignore */
      }
    }
    const state = { events: [], visibleNow: false };
    window.__e2eStepUpProbe = state;
    const readText = () => (panel.textContent || '').replace(/\s+/g, ' ').trim();
    const record = (source) => {
      const visible = !panel.hidden;
      state.visibleNow = visible;
      const text = readText();
      const last = state.events[state.events.length - 1];
      if (!last || last.visible !== visible || last.text !== text) {
        state.events.push({ visible, text, source, at: Date.now() });
      }
    };
    const observer = new MutationObserver(() => record('mutation'));
    observer.observe(panel, { attributes: true, attributeFilter: ['hidden'] });
    window.__e2eStepUpObserver = observer;
    record('init');
    return true;
  });
  if (!installed) {
    throw new Error('step-up panel #stepup-status is missing from the rendered page');
  }
}

async function readStepUpProbe(targetPage) {
  return targetPage.evaluate(() => {
    const probe = window.__e2eStepUpProbe;
    return probe ? JSON.parse(JSON.stringify(probe)) : null;
  });
}

function probeSawVisible(probe) {
  return Boolean(probe && probe.events.some((event) => event.visible));
}

async function waitForVisibleStepUpOr(targetPage, extra, timeout = 15_000) {
  const deadline = Date.now() + timeout;
  let probe = null;
  while (Date.now() < deadline) {
    probe = await readStepUpProbe(targetPage);
    if (probeSawVisible(probe)) return { mode: 'stepup', probe };
    const other = await extra();
    if (other) return { mode: other, probe };
    await delay(50);
  }
  probe = await readStepUpProbe(targetPage);
  if (probeSawVisible(probe)) return { mode: 'stepup', probe };
  return { mode: 'timeout', probe };
}

async function assertVisibleStepUpPanel(targetPage, probe, actionLabel) {
  const visibleEvent = probe && probe.events.find((event) => event.visible);
  if (!visibleEvent) {
    throw new Error(`${actionLabel}: #stepup-status never became visible`);
  }
  if (!visibleEvent.text.includes('Confirm with your passkey')) {
    throw new Error(
      `${actionLabel}: step-up panel text was ${JSON.stringify(visibleEvent.text)}, ` +
        'expected "Confirm with your passkey"',
    );
  }

  const liveVisible = await targetPage
    .locator('#stepup-status')
    .isVisible()
    .catch(() => false);
  if (liveVisible) {
    await targetPage.locator('#stepup-status').waitFor({ state: 'visible', timeout: 5000 });
    const liveText = (await targetPage.locator('#stepup-status').innerText())
      .replace(/\s+/g, ' ')
      .trim();
    if (!liveText.includes('Confirm with your passkey')) {
      throw new Error(
        `${actionLabel}: live step-up panel text was ${JSON.stringify(liveText)}`,
      );
    }
    log(`${actionLabel}: visible step-up panel confirmed: "${oneLine(liveText)}"`);
  } else {
    log(
      `${actionLabel}: step-up panel was visible transiently; ` +
        `MutationObserver captured: "${oneLine(visibleEvent.text)}"`,
    );
  }
  return visibleEvent.text;
}

async function waitForStepUpPanelHidden(targetPage, timeout = 15_000) {
  await targetPage.locator('#stepup-status').waitFor({ state: 'hidden', timeout });
  await delay(50);
  const probe = await readStepUpProbe(targetPage);
  if (!probe) return;
  const firstVisible = probe.events.findIndex((event) => event.visible);
  if (firstVisible >= 0) {
    const hiddenAfter = probe.events
      .slice(firstVisible + 1)
      .some((event) => !event.visible);
    if (!hiddenAfter) {
      throw new Error('#stepup-status became visible but never recorded a hidden transition');
    }
    if (probe.visibleNow) {
      throw new Error('#stepup-status is still visible after the action completed');
    }
  }
}

async function waitForPasskeyCount(targetPage, expected) {
  try {
    await targetPage.waitForFunction(
      ({ selector, count }) => document.querySelectorAll(selector).length >= count,
      { selector: PASSKEY_ITEM_SELECTOR, count: expected },
      { timeout: 25_000 },
    );
  } catch {
    const uiError = await targetPage
      .locator('#add-passkey-error')
      .textContent()
      .catch(() => '');
    throw new Error(
      `passkey count did not reach ${expected}` +
        (uiError ? `: ${oneLine(uiError)}` : ''),
    );
  }
}

function isStepUpProbeUrl(rawUrl) {
  let path = '';
  try {
    path = new URL(rawUrl).pathname;
  } catch {
    return false;
  }
  return (
    path.endsWith('/api/passkeys/add/start') ||
    path.endsWith('/api/passkeys/add/finish') ||
    path.endsWith('/api/sessions/revoke-all') ||
    path.endsWith('/api/recovery/regenerate') ||
    /^\/api\/passkeys\/[^/]+\/revoke$/.test(path) ||
    /^\/api\/sessions\/[^/]+\/revoke$/.test(path)
  );
}

/* ---------- main flow ---------- */

async function runFlow(cfg) {
  const targetPage = page;
  let otpCode = '';
  let recoveryCodes = [];
  let firstSessionCookieValue = '';
  let secondPasskeyAdded = false;
  let addPasskeyStepUpObserved = false;
  let signOutEverywhereStepUpObserved = false;

  await step('Open AuthLayer and show the email sign-in form', async () => {
    const response = await targetPage.goto(`${cfg.baseUrl}/`, { waitUntil: 'domcontentloaded' });
    if (!response || !response.ok()) {
      throw new Error(`GET / returned HTTP ${response ? response.status() : 'no response'}`);
    }
    await targetPage.locator('#email').waitFor({ state: 'visible', timeout: 20_000 });
    await targetPage.getByRole('button', { name: /continue with email/i }).waitFor();
    await targetPage.getByRole('heading', { name: 'Welcome back' }).waitFor();
  });

  await step('Browser is a secure context with WebAuthn APIs', async () => {
    const info = await targetPage.evaluate(() => ({
      secure: window.isSecureContext,
      publicKeyCredential: typeof window.PublicKeyCredential !== 'undefined',
      create: typeof navigator.credentials?.create === 'function',
      get: typeof navigator.credentials?.get === 'function',
    }));
    if (!info.secure) {
      throw new Error(
        'window.isSecureContext is false. Use localhost or HTTPS for WebAuthn.',
      );
    }
    if (!info.publicKeyCredential || !info.create || !info.get) {
      throw new Error('navigator.credentials WebAuthn APIs are not available');
    }
  });

  await step('Request a one-time code for a unique email', async () => {
    await targetPage.locator('#email').fill(cfg.email);
    await targetPage.getByRole('button', { name: /continue with email/i }).click();
    await targetPage.locator('#code').waitFor({ state: 'visible', timeout: 20_000 });
    await targetPage
      .getByRole('heading', { name: /enter your sign-in code/i })
      .waitFor();
  });

  await step('Read the 6-digit code from the page-context dev outbox', async () => {
    otpCode = await readOtpFromOutbox(targetPage, cfg.email);
    if (!/^\d{6}$/.test(otpCode)) throw new Error('unexpected OTP format');
    log(`OTP received for ${cfg.email} (not printed).`);
  });

  await step('Verify the code and receive passkey creation options', async () => {
    await targetPage.locator('#code').fill(otpCode);
    await targetPage.getByRole('button', { name: 'Verify code' }).click();
    await targetPage
      .getByRole('heading', { name: 'Create your passkey' })
      .waitFor({ timeout: 20_000 });
    await targetPage.getByRole('button', { name: 'Create my passkey' }).waitFor();
    await logCeremonyCookie(cfg, 'Registration ceremony');
  });

  await step('Create a passkey with the CDP virtual authenticator', async () => {
    await targetPage.getByRole('button', { name: 'Create my passkey' }).click();
    await waitForAnyHeading(targetPage, ['Save your recovery codes', 'Security dashboard'], 30_000);
  });

  await step('Capture recovery codes and finish registration', async () => {
    const chips = targetPage.locator('.codes-grid .code-chip');
    const onCodesScreen = await targetPage
      .getByRole('heading', { name: 'Save your recovery codes' })
      .isVisible()
      .catch(() => false);

    if (onCodesScreen) {
      await chips.first().waitFor({ state: 'visible', timeout: 10_000 });
      recoveryCodes = (await chips.allTextContents())
        .map((code) => code.trim())
        .filter(Boolean);
      if (recoveryCodes.length === 0) {
        throw new Error('the recovery codes screen rendered no codes');
      }
      const continueButton = targetPage.getByRole('button', { name: /saved them/i });
      await continueButton.waitFor();
      await continueButton.click();
      log(`Captured ${recoveryCodes.length} recovery codes (not printed).`);
    } else {
      log('Recovery codes screen was not shown; checking the dashboard count instead.');
    }

    await targetPage
      .getByRole('heading', { name: 'Security dashboard' })
      .waitFor({ timeout: 25_000 });
  });

  await step('Dashboard shows the email, passkeys, and recovery codes', async () => {
    const dashboardEmail = (await targetPage.locator('.dash-email').innerText())
      .replace(/\s+/g, ' ')
      .trim();
    if (!dashboardEmail.includes(cfg.email)) {
      throw new Error(`dashboard email ${JSON.stringify(dashboardEmail)} does not contain ${cfg.email}`);
    }

    const passkeyCount = Number.parseInt(await readStat(targetPage, 'Passkeys'), 10);
    if (!Number.isFinite(passkeyCount) || passkeyCount < 1) {
      throw new Error('dashboard reports no passkeys');
    }
    const recoveryCount = Number.parseInt(await readStat(targetPage, 'Recovery codes'), 10);
    if (!Number.isFinite(recoveryCount) || recoveryCount < 1) {
      throw new Error('dashboard reports no recovery codes');
    }
    if (recoveryCodes.length > 0 && recoveryCount !== recoveryCodes.length) {
      throw new Error(
        `dashboard recovery count ${recoveryCount} does not match captured ${recoveryCodes.length}`,
      );
    }
    log(`Dashboard verified: 1+ passkey, ${recoveryCount} recovery codes.`);
  });

  await step('Session cookie is HttpOnly and SameSite=Strict (registration)', async () => {
    const cookie = await getSessionCookie(cfg);
    assertSessionCookie(cookie, cfg, 'registration');
    firstSessionCookieValue = cookie.value;
    log(
      `Cookie ${cfg.cookieName}: HttpOnly=${cookie.httpOnly} SameSite=${cookie.sameSite} ` +
        `Secure=${cookie.secure}${cfg.protocol === 'http:' ? ' (local HTTP; Secure=false is expected)' : ''}`,
    );
    await logCeremonyCookie(cfg, 'After registration');
  });

  await step('Log out and clear the session cookie', async () => {
    await targetPage.getByRole('button', { name: 'Log out' }).click();
    await targetPage.locator('#email').waitFor({ state: 'visible', timeout: 20_000 });
    await targetPage.getByRole('heading', { name: 'Welcome back' }).waitFor();
    const cookie = await getSessionCookie(cfg);
    if (cookie && cookie.value) {
      throw new Error('session cookie still has a value after logout');
    }
  });

  await step('Submit the same email and show passkey sign-in', async () => {
    await targetPage.locator('#email').fill(cfg.email);
    await targetPage.getByRole('button', { name: /continue with email/i }).click();
    await targetPage
      .getByRole('button', { name: 'Sign in with passkey' })
      .waitFor({ state: 'visible', timeout: 20_000 });
    if (await targetPage.locator('#code').isVisible().catch(() => false)) {
      throw new Error('server sent a code instead of offering passkey sign-in');
    }
    await logCeremonyCookie(cfg, 'Passkey login ceremony');
  });

  await step('Sign in with the virtual passkey', async () => {
    await targetPage.getByRole('button', { name: 'Sign in with passkey' }).click();
    await targetPage
      .getByRole('heading', { name: 'Security dashboard' })
      .waitFor({ timeout: 30_000 });
    const dashboardEmail = (await targetPage.locator('.dash-email').innerText())
      .replace(/\s+/g, ' ')
      .trim();
    if (!dashboardEmail.includes(cfg.email)) {
      throw new Error('dashboard email is wrong after passkey sign-in');
    }
  });

  await step('Session cookie is HttpOnly and SameSite=Strict (passkey login)', async () => {
    const cookie = await getSessionCookie(cfg);
    assertSessionCookie(cookie, cfg, 'passkey login');
    if (firstSessionCookieValue && cookie.value === firstSessionCookieValue) {
      throw new Error('passkey login reused the previous session token');
    }
    log(
      `Cookie ${cfg.cookieName}: HttpOnly=${cookie.httpOnly} SameSite=${cookie.sameSite} ` +
        `Secure=${cookie.secure}${cfg.protocol === 'http:' ? ' (local HTTP; Secure=false is expected)' : ''}`,
    );
    await logCeremonyCookie(cfg, 'After passkey login');
  });

  /*
   * Add a second passkey through the real UI step-up flow. The sensitive
   * endpoints return 403 stepup_required; static/app.js must show the visible
   * #stepup-status panel, run WebAuthn, finish step-up, and retry.
   *
   * navigator.credentials.get/create are held at page-level gates so the panel
   * and the creation stage can be asserted deterministically. The second
   * virtual authenticator is added only after step-up finishes, just before
   * releasing the creation gate.
   */
  secondPasskeyAdded = await step(
    'Add a second passkey through visible UI step-up (optional)',
    async () => {
      const addButton = targetPage.getByRole('button', { name: 'Add another passkey' });
      if ((await addButton.count()) === 0) {
        throw new Error('UI button "Add another passkey" is missing');
      }

      await installStepUpProbe(targetPage);
      await installStepUpGate(targetPage);
      await installCreateGate(targetPage);
      const before = await targetPage.locator(PASSKEY_ITEM_SELECTOR).count();
      let secondAuthenticatorId = null;

      const responseMark = diagnostics.responses.length;
      try {
        await addButton.click();
        const outcome = await waitForVisibleStepUpOr(
          targetPage,
          async () => {
            const count = await targetPage.locator(PASSKEY_ITEM_SELECTOR).count();
            if (count > before) return 'complete';
            const directStart = diagnostics.responses
              .slice(responseMark)
              .some(
                (entry) =>
                  entry.url.endsWith('/api/passkeys/add/start') && entry.status === 200,
              );
            if (directStart) return 'direct';
            return false;
          },
          15_000,
        );

        const stepUpStarted = diagnostics.responses
          .slice(responseMark)
          .some((entry) => entry.url.endsWith('/api/auth/stepup/start'));
        let mode = outcome.mode;
        let probe = outcome.probe || (await readStepUpProbe(targetPage));
        if (mode !== 'stepup' && probeSawVisible(probe)) mode = 'stepup';

        if (mode === 'timeout') {
          const uiError = await targetPage
            .locator('#add-passkey-error')
            .textContent()
            .catch(() => '');
          throw new Error(
            'add-passkey did not show #stepup-status or start the creation prompt' +
              (uiError ? `: ${oneLine(uiError)}` : ''),
          );
        }

        if (mode === 'stepup') {
          addPasskeyStepUpObserved = true;
          await assertVisibleStepUpPanel(targetPage, probe, 'Add passkey');
          stepUpEvidence.push(
            'add-passkey: visible #stepup-status with "Confirm with your passkey"',
          );
          await waitForStepUpGateEntered(targetPage);
          await logCeremonyCookie(cfg, 'Add-passkey step-up ceremony');
          log('Step-up panel is visible and the UI is waiting at WebAuthn; releasing the step-up gate.');
          await releaseStepUpGate(targetPage);
        } else if (stepUpStarted) {
          throw new Error(
            'step-up API ran but the visible #stepup-status panel was never observed',
          );
        } else {
          log(
            'Step-up was not required for add-passkey; ' +
              'the passkey creation prompt started directly.',
          );
          stepUpEvidence.push(
            'add-passkey: step-up not required (creation prompt started directly)',
          );
        }

        try {
          await waitForCreateGateEntered(targetPage, 15_000);
        } catch {
          const uiError = await targetPage
            .locator('#add-passkey-error')
            .textContent()
            .catch(() => '');
          throw new Error(
            'UI did not reach the passkey creation prompt' +
              (uiError ? `: ${oneLine(uiError)}` : ''),
          );
        }
        log('Passkey creation prompt reached; adding the second authenticator.');
        await logCeremonyCookie(cfg, 'Add-passkey registration ceremony');

        secondAuthenticatorId = await addVirtualAuthenticator(cdpSession, 'usb');
        authenticatorIds.push(secondAuthenticatorId);
        log(`Added second virtual authenticator ${secondAuthenticatorId}.`);
        await releaseCreateGate(targetPage);

        await waitForPasskeyCount(targetPage, before + 1);
        await waitForStepUpPanelHidden(targetPage);
        await logCeremonyCookie(cfg, 'After add-passkey');

        const after = await targetPage.locator(PASSKEY_ITEM_SELECTOR).count();
        if (after < before + 1) throw new Error('passkey list did not grow');
        const addError = await targetPage
          .locator('#add-passkey-error')
          .textContent()
          .catch(() => '');
        if (addError && addError.trim()) {
          throw new Error(`add-passkey error remains: ${oneLine(addError)}`);
        }
        log(`Passkey count: ${before} -> ${after}.`);
      } finally {
        await releaseStepUpGate(targetPage).catch(() => {});
        await releaseCreateGate(targetPage).catch(() => {});
        await restoreStepUpGate(targetPage);
        await restoreCreateGate(targetPage);
        if (secondAuthenticatorId) {
          await removeVirtualAuthenticator(secondAuthenticatorId);
        }
      }
    },
    { optional: true },
  );

  if (!secondPasskeyAdded) {
    skipStep('Revoke a passkey (optional)', 'second passkey was not added');
  } else {
    await step(
      'Revoke the added passkey through the UI (optional)',
      async () => {
        const before = await targetPage.locator(PASSKEY_ITEM_SELECTOR).count();
        if (before < 2) throw new Error('expected at least two passkeys before revoke');

        const lastItem = targetPage.locator(PASSKEY_ITEM_SELECTOR).last();
        await lastItem.getByRole('button', { name: 'Remove' }).click();
        const dialog = targetPage.locator('dialog[open]');
        await dialog.waitFor({ state: 'visible', timeout: 10_000 });
        await dialog.getByRole('button', { name: 'Remove passkey' }).click();

        try {
          await targetPage.waitForFunction(
            ({ selector, expected }) =>
              document.querySelectorAll(selector).length <= expected,
            { selector: PASSKEY_ITEM_SELECTOR, expected: before - 1 },
            { timeout: 25_000 },
          );
        } catch {
          const uiError = await targetPage
            .locator('.item-error')
            .last()
            .textContent()
            .catch(() => '');
          throw new Error(
            `passkey was not revoked${uiError ? `: ${oneLine(uiError)}` : ''}`,
          );
        }
        log(`Passkey count: ${before} -> ${await targetPage.locator(PASSKEY_ITEM_SELECTOR).count()}.`);
      },
      { optional: true },
    );
  }

  /*
   * The add/revoke steps left a valid 5-minute step-up timestamp on this
   * session. Log out and sign in again so "Sign out everywhere" must run a
   * fresh visible step-up.
   */
  await step('Log out and sign in again for a fresh step-up state', async () => {
    await targetPage.getByRole('button', { name: 'Log out' }).click();
    await targetPage.locator('#email').waitFor({ state: 'visible', timeout: 20_000 });
    await targetPage.locator('#email').fill(cfg.email);
    await targetPage.getByRole('button', { name: /continue with email/i }).click();
    await targetPage
      .getByRole('button', { name: 'Sign in with passkey' })
      .waitFor({ state: 'visible', timeout: 20_000 });
    await targetPage.getByRole('button', { name: 'Sign in with passkey' }).click();
    await targetPage
      .getByRole('heading', { name: 'Security dashboard' })
      .waitFor({ timeout: 30_000 });
  });

  const signOutEverywhere = targetPage
    .locator('section.panel[aria-labelledby="sessions-heading"]')
    .getByRole('button', { name: 'Sign out everywhere' });

  if ((await signOutEverywhere.count()) === 0) {
    skipStep(
      'Sign out everywhere with visible UI step-up',
      'UI button "Sign out everywhere" was not found in the sessions panel',
    );
  } else {
    await step('Sign out everywhere with visible UI step-up', async () => {
      await installStepUpProbe(targetPage);
      await installStepUpGate(targetPage);
      const responseMark = diagnostics.responses.length;

      try {
        await signOutEverywhere.click();
        const dialog = targetPage.locator('dialog[open]');
        await dialog.waitFor({ state: 'visible', timeout: 10_000 });
        await dialog
          .getByRole('heading', { name: 'Sign out everywhere?' })
          .waitFor({ timeout: 5000 });
        await dialog.getByRole('button', { name: 'Sign out everywhere' }).click();

        const outcome = await waitForVisibleStepUpOr(
          targetPage,
          async () => {
            const signedOut = await targetPage
              .locator('#email')
              .isVisible()
              .catch(() => false);
            if (signedOut) return 'complete';
            const revokeAllOk = diagnostics.responses
              .slice(responseMark)
              .some(
                (entry) =>
                  entry.url.endsWith('/api/sessions/revoke-all') &&
                  entry.status === 200,
              );
            if (revokeAllOk) return 'direct';
            return false;
          },
          15_000,
        );

        const stepUpStarted = diagnostics.responses
          .slice(responseMark)
          .some((entry) => entry.url.endsWith('/api/auth/stepup/start'));
        let mode = outcome.mode;
        let probe = outcome.probe || (await readStepUpProbe(targetPage));
        if (mode !== 'stepup' && probeSawVisible(probe)) mode = 'stepup';

        if (mode === 'timeout') {
          const uiError = await targetPage
            .locator('#sessions-action-error')
            .textContent()
            .catch(() => '');
          throw new Error(
            'sign out everywhere did not finish' +
              (uiError ? `: ${oneLine(uiError)}` : ''),
          );
        }

        if (mode === 'stepup') {
          signOutEverywhereStepUpObserved = true;
          await assertVisibleStepUpPanel(targetPage, probe, 'Sign out everywhere');
          stepUpEvidence.push(
            'sign-out-everywhere: visible #stepup-status with "Confirm with your passkey"',
          );
          await waitForStepUpGateEntered(targetPage);
          await logCeremonyCookie(cfg, 'Sign-out step-up ceremony');
          log('Sign-out step-up panel is visible; releasing the WebAuthn gate.');
          await releaseStepUpGate(targetPage);
        } else if (stepUpStarted) {
          throw new Error(
            'step-up API ran but the visible #stepup-status panel was never observed for sign-out',
          );
        } else {
          log('Step-up was not required for sign out everywhere.');
          stepUpEvidence.push('sign-out-everywhere: step-up not required');
        }

        await targetPage.locator('#email').waitFor({ state: 'visible', timeout: 25_000 });
        await targetPage.getByRole('heading', { name: 'Welcome back' }).waitFor();
        await waitForStepUpPanelHidden(targetPage);

        const signedOutText = (await targetPage.locator('.auth-card').innerText())
          .replace(/\s+/g, ' ')
          .trim();
        if (!/signed out of every device/i.test(signedOutText)) {
          throw new Error('sign-out-everywhere success notice is missing');
        }

        const cookie = await getSessionCookie(cfg);
        if (cookie && cookie.value) {
          throw new Error('session cookie still exists after sign out everywhere');
        }
        const revokeAllSucceeded = diagnostics.responses
          .slice(responseMark)
          .some(
            (entry) =>
              entry.url.endsWith('/api/sessions/revoke-all') && entry.status === 200,
          );
        if (!revokeAllSucceeded) {
          throw new Error('revoke-all did not return HTTP 200');
        }
        await logCeremonyCookie(cfg, 'After sign out everywhere');
        log('Signed out everywhere; UI returned to signed-out state and the cookie was cleared.');
      } finally {
        await releaseStepUpGate(targetPage).catch(() => {});
        await restoreStepUpGate(targetPage);
      }
    });
  }

  log(
    `Visible step-up panel exercised: add-passkey=${addPasskeyStepUpObserved}, ` +
      `sign-out-everywhere=${signOutEverywhereStepUpObserved}`,
  );

  await step('No uncaught page errors or console errors', async () => {
    const activeConsoleErrors = diagnostics.consoleErrors.filter(
      (entry) => !entry.tolerated,
    );
    const toleratedStepUpNoise = [];
    const unexpectedConsoleErrors = [];
    for (const entry of activeConsoleErrors) {
      if (
        /failed to load resource/i.test(entry.text) &&
        /\b403\b/.test(entry.text) &&
        entry.url &&
        isStepUpProbeUrl(entry.url) &&
        diagnostics.responses.some(
          (response) => response.status === 403 && response.url === entry.url,
        )
      ) {
        // The UI intentionally probes a step-up-protected endpoint, receives
        // 403 stepup_required, then completes WebAuthn and retries. Chrome
        // reports that rejected fetch as a console error.
        toleratedStepUpNoise.push(entry);
      } else {
        unexpectedConsoleErrors.push(entry);
      }
    }

    const skippedNoise = diagnostics.consoleErrors.length - activeConsoleErrors.length;
    if (skippedNoise > 0) {
      log(`${skippedNoise} console error(s) from skipped optional steps were tolerated.`);
    }
    if (toleratedStepUpNoise.length > 0) {
      log(
        `${toleratedStepUpNoise.length} expected 403 step-up probe console ` +
          `error(s) were tolerated.`,
      );
    }
    if (diagnostics.pageErrors.length > 0) {
      throw new Error(
        `${diagnostics.pageErrors.length} uncaught page error(s):\n` +
          diagnostics.pageErrors.map((entry) => entry.text).join('\n'),
      );
    }
    if (unexpectedConsoleErrors.length > 0) {
      throw new Error(
        `${unexpectedConsoleErrors.length} console error(s):\n` +
          unexpectedConsoleErrors
            .map((entry) => `${entry.text}${entry.url ? ` (${entry.url})` : ''}`)
            .join('\n'),
      );
    }
  });
}

/* ---------- summary / entrypoint ---------- */

function printSummary(cfg) {
  const passed = results.filter((entry) => entry.status === 'PASS').length;
  console.log('');
  console.log('=== AuthLayer browser E2E summary ===');
  console.log(`Base URL : ${cfg ? cfg.baseUrl : ENV.baseUrl}`);
  console.log(`Email    : ${EMAIL}`);
  console.log(`Chrome   : ${ENV.chromePath}`);
  console.log(
    `Headless : ${cfg ? cfg.headless : ENV.headless}` +
      (headedFallbackUsed ? ' (headed fallback used)' : ''),
  );
  console.log(`Server   : ${cfg && cfg.startServer ? 'spawned by this run' : 'already running'}`);
  console.log(
    `Step-up  : ${stepUpEvidence.length > 0 ? stepUpEvidence.join(' | ') : 'no visible panel observed'}`,
  );
  console.log(`Result   : PASS ${passed} | FAIL ${failures} | SKIP ${skips}`);
  for (const entry of results) {
    if (entry.status === 'SKIP') console.log(`  SKIP ${entry.name}: ${entry.detail || ''}`);
  }
  if (diagnostics.requestFailures.length > 0) {
    console.log(`Network failures observed (informational): ${diagnostics.requestFailures.length}`);
    for (const entry of diagnostics.requestFailures.slice(0, 10)) {
      console.log(`  ${entry.method} ${entry.url} -> ${entry.error}`);
    }
  }
  if (diagnostics.serverErrors.length > 0) {
    console.log(`HTTP 5xx responses observed (informational): ${diagnostics.serverErrors.length}`);
    for (const entry of diagnostics.serverErrors.slice(0, 10)) {
      console.log(`  ${entry.status} ${entry.url}`);
    }
  }
  console.log(failures === 0 ? 'E2E RESULT: PASS' : 'E2E RESULT: FAIL');
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    log(`Received ${signal}; stopping server and browser.`);
    cleanup()
      .catch(() => {})
      .finally(() => process.exit(130));
  });
}

process.on('exit', () => {
  if (serverChild && serverChild.exitCode === null) {
    try {
      serverChild.kill();
    } catch {
      /* best effort */
    }
  }
});

let config = null;
try {
  config = loadConfig();
  log(`AuthLayer browser E2E (run ${RUN_ID})`);
  log(`Base URL: ${config.baseUrl}`);
  log(`Test email: ${config.email}`);
  log(`Database: ${config.databasePath}${config.startServer ? '' : ' (not used; external server)'}`);

  if (config.startServer) {
    await startServer(config);
  } else {
    await ensureExternalServer(config);
  }

  const setup = await setupBrowser(config);
  browser = setup.browser;
  browserContext = setup.context;
  page = setup.page;
  cdpSession = setup.cdp;
  authenticatorIds = [setup.authenticatorId];
  attachDiagnostics(page);

  await runFlow(config);
} catch (error) {
  if (!(error instanceof StepAbort)) {
    failures += 1;
    log(`FAIL harness: ${oneLine(error.message)}`);
    if (error.stack) logDetail(error.stack);
  }
} finally {
  await cleanup();
}

printSummary(config);
process.exitCode = failures > 0 ? 1 : 0;
