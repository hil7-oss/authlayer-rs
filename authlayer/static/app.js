/*
 * AuthLayer browser client.
 *
 * Vanilla JS only. The session lives in an HttpOnly cookie; this file never
 * stores credentials, codes, or recovery codes in web storage.
 */
(() => {
  'use strict';

  const API = {
    me: '/api/me',
    start: '/api/auth/start',
    verifyCode: '/api/auth/verify-code',
    passkeyRegister: '/api/auth/passkey/register',
    passkeyLogin: '/api/auth/passkey/login',
    stepUpStart: '/api/auth/stepup/start',
    stepUpFinish: '/api/auth/stepup/finish',
    logout: '/api/auth/logout',
    passkeys: '/api/passkeys',
    passkeysAddStart: '/api/passkeys/add/start',
    passkeysAddFinish: '/api/passkeys/add/finish',
    sessions: '/api/sessions',
    sessionsRevokeAll: '/api/sessions/revoke-all',
    recoveryRegenerate: '/api/recovery/regenerate',
    recoverStart: '/api/auth/recover/start',
    recoverVerifyEmail: '/api/auth/recover/verify-email',
    recoverVerifyCode: '/api/auth/recover/verify-code',
  };

  const app = document.getElementById('app');
  const toastEl = document.getElementById('toast');
  if (!app) return;

  const state = {
    email: '',
    devOutbox: null,
    challengeId: null,
    loginOptions: null,
    registerOptions: null,
    registerReason: 'signin',
    recoveryChallengeId: null,
    pendingCodes: null,
    codesContext: 'register',
    me: null,
    dashboard: null,
    dashAlert: null,
  };

  const SVG_NS = 'http://www.w3.org/2000/svg';
  let toastTimer = null;
  let activeStepUp = null;

  const ICONS = {
    alert: [
      ['path', { d: 'M12 3.4 21 19.4H3L12 3.4z' }],
      ['path', { d: 'M12 9.3v4.2' }],
      ['path', { d: 'M12 16.6h.01' }],
    ],
    arrowLeft: [
      ['path', { d: 'M19 12H5' }],
      ['path', { d: 'M12 19l-7-7 7-7' }],
    ],
    check: [['path', { d: 'M20 6 9 17l-5-5' }]],
    clock: [
      ['circle', { cx: '12', cy: '12', r: '8.6' }],
      ['path', { d: 'M12 7.4V12l3.1 1.9' }],
    ],
    copy: [
      ['rect', { x: '9', y: '9', width: '11', height: '11', rx: '2' }],
      ['path', { d: 'M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3' }],
    ],
    device: [
      ['rect', { x: '3', y: '4.5', width: '18', height: '12.5', rx: '2' }],
      ['path', { d: 'M8 21h8' }],
      ['path', { d: 'M12 17v4' }],
    ],
    external: [
      ['path', { d: 'M14 4h6v6' }],
      ['path', { d: 'M20 4 11 13' }],
      ['path', { d: 'M18 14.5V19a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h4.5' }],
    ],
    key: [
      ['circle', { cx: '8.1', cy: '15.9', r: '3.2' }],
      ['path', { d: 'm10.5 13.5 8-8' }],
      ['path', { d: 'm15.8 8.2 2 2' }],
      ['path', { d: 'm18 6 2 2' }],
    ],
    logout: [
      ['path', { d: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4' }],
      ['path', { d: 'm16 17 5-5-5-5' }],
      ['path', { d: 'M21 12H9' }],
    ],
    mail: [
      ['rect', { x: '3', y: '5', width: '18', height: '14', rx: '2.5' }],
      ['path', { d: 'm3.8 6.6 8.2 6.2 8.2-6.2' }],
    ],
    refresh: [
      ['path', { d: 'M21 12a9 9 0 1 1-2.6-6.4' }],
      ['path', { d: 'M21 3v6h-6' }],
    ],
    shield: [
      ['path', { d: 'M12 3.1l7.2 2.9v5.4c0 4.5-3 7.7-7.2 9.1-4.2-1.4-7.2-4.6-7.2-9.1V6z' }],
      ['path', { d: 'm9 11.8 2 2 4-4' }],
    ],
    trash: [
      ['path', { d: 'M4 7h16' }],
      ['path', { d: 'M9.5 7V4.5h5V7' }],
      ['path', { d: 'm6.5 7 .9 13h9.2l.9-13' }],
      ['path', { d: 'M10 11v5.5' }],
      ['path', { d: 'M14 11v5.5' }],
    ],
  };

  /* ---------- DOM helpers ---------- */

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      if (props.class) node.className = props.class;
      if (props.text !== undefined && props.text !== null) node.textContent = String(props.text);
      if (props.attrs) {
        for (const [key, value] of Object.entries(props.attrs)) {
          if (value === undefined || value === null || value === false) continue;
          node.setAttribute(key, value === true ? '' : String(value));
        }
      }
      if (props.dataset) {
        for (const [key, value] of Object.entries(props.dataset)) {
          if (value !== undefined && value !== null) node.dataset[key] = String(value);
        }
      }
      if (props.props) {
        for (const [key, value] of Object.entries(props.props)) {
          node[key] = value;
        }
      }
      if (props.on) {
        for (const [event, handler] of Object.entries(props.on)) {
          node.addEventListener(event, handler);
        }
      }
    }
    appendChildren(node, children);
    return node;
  }

  function appendChildren(node, children) {
    for (const child of children) {
      if (child === null || child === undefined || child === false || child === true) continue;
      if (Array.isArray(child)) {
        appendChildren(node, child);
      } else if (child instanceof Node) {
        node.appendChild(child);
      } else {
        node.appendChild(document.createTextNode(String(child)));
      }
    }
  }

  function icon(name) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    svg.setAttribute('class', 'icon');
    for (const [tag, attrs] of ICONS[name] || []) {
      const child = document.createElementNS(SVG_NS, tag);
      for (const [key, value] of Object.entries(attrs)) child.setAttribute(key, value);
      svg.appendChild(child);
    }
    return svg;
  }

  function spinner() {
    return h('span', { class: 'spinner', attrs: { 'aria-hidden': 'true' } });
  }

  function button(label, options = {}) {
    const kind = options.kind || 'secondary';
    const classes = ['btn', `btn-${kind}`];
    if (options.size === 'sm') classes.push('btn-sm');
    if (options.block) classes.push('btn-block');
    if (options.className) classes.push(options.className);
    const attrs = { type: options.type || 'button' };
    if (options.ariaLabel) attrs['aria-label'] = options.ariaLabel;
    return h(
      'button',
      {
        class: classes.join(' '),
        attrs,
        on: options.onClick ? { click: options.onClick } : null,
      },
      options.iconName ? icon(options.iconName) : null,
      h('span', { class: 'btn-label' }, label),
    );
  }

  function badge(text, className = 'badge-muted') {
    return h('span', { class: `badge ${className}` }, text);
  }

  function liveError(id) {
    return h('div', {
      class: 'alert alert-error',
      attrs: {
        ...(id ? { id } : {}),
        role: 'alert',
        'aria-atomic': 'true',
        hidden: true,
      },
    });
  }

  function setLiveError(box, message, action = null) {
    if (!box) return;
    if (!message) {
      box.hidden = true;
      box.replaceChildren();
      return;
    }
    const body = h('div', { class: 'alert-body' }, h('p', null, message));
    if (action) body.appendChild(h('div', { class: 'alert-action' }, action));
    box.replaceChildren(icon('alert'), body);
    box.hidden = false;
  }

  function setStatus(box, message, iconName = 'check') {
    if (!box) return;
    if (!message) {
      box.hidden = true;
      box.replaceChildren();
      return;
    }
    box.replaceChildren(icon(iconName), h('div', { class: 'alert-body' }, h('p', null, message)));
    box.hidden = false;
  }

  function alertBox(kind, content, options = {}) {
    const iconName =
      options.iconName ||
      (kind === 'error' || kind === 'warning' ? 'alert' : kind === 'success' ? 'check' : 'shield');
    return h(
      'div',
      {
        class: `alert alert-${kind}`,
        attrs: { role: kind === 'error' ? 'alert' : 'status' },
      },
      icon(iconName),
      h('div', { class: 'alert-body' }, content),
    );
  }

  function noticeBanner(notice) {
    if (!notice || !notice.message) return null;
    return alertBox(notice.kind || 'info', h('p', null, notice.message));
  }

  function mount(node, focusId = null) {
    clearToast();
    app.replaceChildren(node);
    if (!focusId) window.scrollTo(0, 0);
    const target = focusId ? document.getElementById(focusId) : node.querySelector('.screen-title');
    if (target) {
      requestAnimationFrame(() => {
        try {
          target.focus({ preventScroll: !focusId });
        } catch {
          target.focus();
        }
      });
    }
  }

  function setButtonBusy(target, busy, label = 'Working…') {
    if (!target) return;
    if (busy) {
      if (!target._idleChildren) {
        target._idleChildren = Array.from(target.childNodes).map((node) => node.cloneNode(true));
      }
      target.classList.add('is-busy');
      target.setAttribute('aria-busy', 'true');
      target.replaceChildren(spinner(), h('span', { class: 'btn-label' }, label));
    } else {
      target.classList.remove('is-busy');
      target.removeAttribute('aria-busy');
      if (target._idleChildren) {
        target.replaceChildren(...target._idleChildren.map((node) => node.cloneNode(true)));
      }
    }
  }

  async function withBusy(target, busyLabel, scope, work) {
    const container = scope || app;
    const buttons = Array.from(container.querySelectorAll('button'));
    const previousDisabled = buttons.map((item) => item.disabled);
    const previousBusy = container.getAttribute('aria-busy');
    container.setAttribute('aria-busy', 'true');
    for (const item of buttons) item.disabled = true;
    if (target) setButtonBusy(target, true, busyLabel);
    try {
      return await work();
    } finally {
      if (target && target.isConnected) setButtonBusy(target, false);
      buttons.forEach((item, index) => {
        if (item.isConnected) item.disabled = previousDisabled[index];
      });
      if (container.isConnected) {
        if (previousBusy === null) container.removeAttribute('aria-busy');
        else container.setAttribute('aria-busy', previousBusy);
      }
    }
  }

  function flashButtonLabel(target, label, delay = 1800) {
    const span = target && target.querySelector('.btn-label');
    if (!span) return;
    if (span.dataset.originalLabel === undefined) span.dataset.originalLabel = span.textContent;
    span.textContent = label;
    window.setTimeout(() => {
      if (span.isConnected) span.textContent = span.dataset.originalLabel;
    }, delay);
  }

  function showToast(message) {
    if (!toastEl) return;
    window.clearTimeout(toastTimer);
    toastEl.textContent = message;
    toastEl.hidden = false;
    requestAnimationFrame(() => toastEl.classList.add('show'));
    toastTimer = window.setTimeout(() => {
      toastEl.classList.remove('show');
      toastTimer = window.setTimeout(() => {
        toastEl.hidden = true;
        toastEl.textContent = '';
      }, 220);
    }, 4200);
  }

  function clearToast() {
    window.clearTimeout(toastTimer);
    toastTimer = null;
    if (!toastEl) return;
    toastEl.classList.remove('show');
    toastEl.hidden = true;
    toastEl.textContent = '';
  }

  function setStepUpStatus(visible) {
    const status = document.getElementById('stepup-status');
    if (!status) return;
    if (visible) {
      clearToast();
      status.hidden = false;
    } else {
      status.hidden = true;
    }
  }

  function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
    return new Promise((resolve) => {
      let settled = false;
      const previousFocus = document.activeElement;
      const finish = (value) => {
        if (settled) return;
        settled = true;
        try {
          if (dialog.open) dialog.close();
        } catch {
          /* already closed */
        }
        dialog.remove();
        if (previousFocus && previousFocus.isConnected && typeof previousFocus.focus === 'function') {
          try {
            previousFocus.focus({ preventScroll: true });
          } catch {
            /* focus restoration is best-effort */
          }
        }
        resolve(value);
      };

      const cancelButton = button(cancelLabel, {
        kind: 'secondary',
        onClick: () => finish(false),
      });
      const confirmButton = button(confirmLabel, {
        kind: danger ? 'danger' : 'primary',
        onClick: () => finish(true),
      });
      const dialog = h(
        'dialog',
        {
          class: 'modal',
          attrs: {
            'aria-labelledby': 'confirm-title',
            'aria-describedby': 'confirm-text',
          },
        },
        h(
          'div',
          { class: 'modal-card' },
          h('h2', { class: 'modal-title', attrs: { id: 'confirm-title' } }, title),
          h('p', { class: 'modal-text', attrs: { id: 'confirm-text' } }, message),
          h('div', { class: 'modal-actions' }, cancelButton, confirmButton),
        ),
      );

      dialog.addEventListener('cancel', (event) => {
        event.preventDefault();
        finish(false);
      });
      dialog.addEventListener('click', (event) => {
        if (event.target === dialog) finish(false);
      });
      dialog.addEventListener('close', () => finish(false));

      document.body.appendChild(dialog);
      if (typeof dialog.showModal !== 'function') {
        dialog.remove();
        resolve(window.confirm(`${title}\n\n${message}`));
        return;
      }
      dialog.showModal();
      requestAnimationFrame(() => cancelButton.focus());
    });
  }

  /* ---------- API ---------- */

  class ApiError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = 'ApiError';
      this.status = options.status || 0;
      this.code = options.code || '';
      this.serverMessage = options.serverMessage || '';
      this.network = Boolean(options.network);
    }
  }

  class StepUpError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = 'StepUpError';
      this.userMessage = message;
      this.status = options.status || 0;
      this.unauthorized = Boolean(options.unauthorized);
    }
  }

  async function api(path, { method = 'GET', body = null } = {}) {
    const headers = { Accept: 'application/json' };
    const init = {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
    };
    if (body !== null) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    let response;
    try {
      response = await fetch(path, init);
    } catch {
      throw new ApiError('network', { network: true });
    }

    let text = '';
    try {
      text = await response.text();
    } catch {
      text = '';
    }

    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }

    if (!response.ok) {
      throw new ApiError(`HTTP ${response.status}`, {
        status: response.status,
        code: data && typeof data.error === 'string' ? data.error : '',
        serverMessage: data && typeof data.message === 'string' ? data.message : '',
      });
    }

    return data && typeof data === 'object' ? data : {};
  }

  const ERROR_COPY = {
    invalid_email: 'That email address doesn’t look right. Check it and try again.',
    user_not_found: 'We couldn’t find an account with that email address. Check it and try again.',
    too_many_attempts: 'That code has had too many incorrect tries. Request a new code.',
    invalid_code: 'That code isn’t right. Check the email and try again.',
    code_not_found: 'We couldn’t find a sign-in code for that email. Request a new one.',
    code_already_used: 'That code has already been used. Request a new one.',
    code_expired: 'That code has expired. Request a new one.',
    use_passkey: 'This account is protected with a passkey. Use your passkey to sign in.',
    challenge_not_found: 'That step has expired. Please start again.',
    challenge_expired: 'That took too long. Please start again.',
    credential_already_registered: 'This device already has a passkey saved for AuthLayer. Try signing in with it.',
    passkey_not_found: 'We couldn’t find that passkey on your account. Please try again.',
    invalid_id: 'That item is no longer available. Refresh the page and try again.',
    cannot_remove_last_credential:
      'You can’t remove your only passkey while you have no recovery codes. Generate recovery codes first.',
    invalid_recovery_code: 'That recovery code didn’t work. Check it and try again.',
    no_passkeys: 'You need a passkey to confirm this change. Sign out and sign in with an email code to create one.',
  };

  function humanizeError(error, fallback) {
    if (error instanceof StepUpError) {
      return error.userMessage;
    }
    if (!(error instanceof ApiError)) {
      return fallback || 'Something went wrong. Please try again.';
    }
    if (error.network) {
      return 'We couldn’t reach AuthLayer. Check your connection and try again.';
    }
    if (error.status === 401 || error.code === 'unauthenticated') {
      return 'Your session has ended. Please sign in again.';
    }
    if (error.status === 429 || error.code === 'too_many_requests') {
      return 'Too many attempts. Please wait a few minutes and try again.';
    }
    if (error.code === 'forbidden') {
      return 'That request was blocked for safety. Reload the page and try again.';
    }
    if (error.code === 'webauthn_error') {
      return 'We couldn’t verify your device. Please try again.';
    }
    if (error.status >= 500) {
      return 'Something went wrong on our side. Please try again in a moment.';
    }
    return ERROR_COPY[error.serverMessage] || fallback || 'Something went wrong. Please try again.';
  }

  function isStepUpRequired(error) {
    return (
      error instanceof ApiError &&
      error.status === 403 &&
      (error.code === 'stepup_required' || error.serverMessage === 'stepup_required')
    );
  }

  function isUnauthorizedError(error) {
    return error instanceof ApiError && error.status === 401;
  }

  function unauthorizedResult(result) {
    return result.status === 'rejected' && isUnauthorizedError(result.reason);
  }

  /* ---------- Formatting and small utilities ---------- */

  function parseServerDate(value) {
    if (typeof value !== 'string' || !value.trim()) return null;
    let input = value.trim().replace(' ', 'T');
    input = input.replace(/(\.\d{3})\d+/, '$1');
    const date = new Date(input);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value, { withTime = false } = {}) {
    const date = parseServerDate(value);
    if (!date) return 'unknown';
    try {
      return new Intl.DateTimeFormat(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        ...(withTime ? { hour: 'numeric', minute: '2-digit' } : {}),
      }).format(date);
    } catch {
      return withTime ? date.toLocaleString() : date.toLocaleDateString();
    }
  }

  function relativeTime(value) {
    const date = parseServerDate(value);
    if (!date) return '';
    const diff = date.getTime() - Date.now();
    const absolute = Math.abs(diff);
    if (absolute < 45000) return 'just now';

    const format = (amount, unit) => {
      try {
        return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(amount, unit);
      } catch {
        const count = Math.abs(amount);
        const suffix = count === 1 ? '' : 's';
        return amount >= 0 ? `in ${count} ${unit}${suffix}` : `${count} ${unit}${suffix} ago`;
      }
    };

    if (absolute < 3600000) return format(Math.round(diff / 60000), 'minute');
    if (absolute < 86400000) return format(Math.round(diff / 3600000), 'hour');
    if (absolute < 2592000000) return format(Math.round(diff / 86400000), 'day');
    if (absolute < 31536000000) return format(Math.round(diff / 2592000000), 'month');
    return format(Math.round(diff / 31536000000), 'year');
  }

  function dateSpan(value, options = {}) {
    const date = parseServerDate(value);
    return h(
      'span',
      { attrs: date ? { title: date.toLocaleString() } : null },
      formatDate(value, options),
    );
  }

  function relativeSpan(value) {
    const date = parseServerDate(value);
    const text = relativeTime(value) || 'unknown';
    return h('span', { attrs: date ? { title: date.toLocaleString() } : null }, text);
  }

  function describeUserAgent(value) {
    if (typeof value !== 'string' || !value.trim()) return 'Unknown device';
    const ua = value;
    let browser = 'Browser';
    if (/EdgiOS\/|Edg\//.test(ua)) browser = 'Edge';
    else if (/OPR\/|Opera/.test(ua)) browser = 'Opera';
    else if (/FxiOS\/|Firefox\//.test(ua)) browser = 'Firefox';
    else if (/CriOS\/|Chrome\//.test(ua)) browser = 'Chrome';
    else if (/Safari\//.test(ua)) browser = 'Safari';

    let os = '';
    if (/Windows/.test(ua)) os = 'Windows';
    else if (/iPhone|iPod/.test(ua)) os = 'iOS';
    else if (/iPad/.test(ua)) os = 'iPadOS';
    else if (/Android/.test(ua)) os = 'Android';
    else if (/Macintosh|Mac OS X/.test(ua)) os = 'macOS';
    else if (/CrOS/.test(ua)) os = 'ChromeOS';
    else if (/Linux/.test(ua)) os = 'Linux';

    return os ? `${browser} on ${os}` : browser;
  }

  function safeInternalPath(value) {
    if (typeof value !== 'string') return null;
    if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return null;
    return value;
  }

  function emailFrom(data, fallback) {
    return data && typeof data.email === 'string' && data.email ? data.email : fallback;
  }

  function countOr(value, fallback) {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed >= 0) return String(Math.trunc(parsed));
    return String(fallback);
  }

  function isValidEmail(value) {
    if (!value || /\s/.test(value)) return false;
    const at = value.indexOf('@');
    return at > 0 && at < value.length - 1 && value.indexOf('@', at + 1) === -1;
  }

  function formatRecoveryInput(value) {
    const cleaned = value
      .toUpperCase()
      .replace(/[^A-Z0-9_-]/g, '')
      .replace(/-/g, '')
      .slice(0, 12);
    const groups = [];
    for (let index = 0; index < cleaned.length; index += 4) {
      groups.push(cleaned.slice(index, index + 4));
    }
    return groups.join('-');
  }

  async function copyText(text) {
    try {
      if (
        navigator.clipboard &&
        typeof navigator.clipboard.writeText === 'function' &&
        (typeof window.isSecureContext !== 'boolean' || window.isSecureContext)
      ) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch {
      /* fall back below */
    }

    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.top = '-1000px';
    area.style.opacity = '0';
    document.body.appendChild(area);
    const selection = document.getSelection();
    const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
    area.select();
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch {
      copied = false;
    }
    area.remove();
    if (previousRange && selection) {
      try {
        selection.removeAllRanges();
        selection.addRange(previousRange);
      } catch {
        /* selection restore is best-effort */
      }
    }
    return copied;
  }

  /* ---------- Base64url and WebAuthn ---------- */

  const b64url = {
    encode(value) {
      let bytes;
      if (value instanceof Uint8Array) bytes = value;
      else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
      else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      else throw new TypeError('Expected binary data');

      let binary = '';
      const chunkSize = 0x8000;
      for (let index = 0; index < bytes.length; index += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
      }
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    decode(value) {
      if (typeof value !== 'string') throw new TypeError('Expected base64url text');
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return bytes;
    },
  };

  function webauthnSupportMessage() {
    if (typeof window.isSecureContext === 'boolean' && !window.isSecureContext) {
      return 'Passkeys need a secure connection. Open AuthLayer over HTTPS (localhost is okay for development).';
    }
    if (!window.PublicKeyCredential) {
      return 'Passkeys aren’t available in this browser. Use a recent version of Chrome, Edge, Safari, or Firefox on a device with a screen lock.';
    }
    if (
      !navigator.credentials ||
      typeof navigator.credentials.create !== 'function' ||
      typeof navigator.credentials.get !== 'function'
    ) {
      return 'This browser can’t use passkeys. Try another browser or device.';
    }
    return null;
  }

  function getPublicKey(options) {
    const publicKey = options && typeof options === 'object' ? options.publicKey : null;
    if (!publicKey || typeof publicKey !== 'object') throw new Error('invalid_webauthn_options');
    return publicKey;
  }

  function decodeDescriptors(list) {
    if (!Array.isArray(list)) return null;
    return list.map((descriptor) => {
      if (!descriptor || typeof descriptor.id !== 'string') throw new Error('invalid_webauthn_options');
      return { ...descriptor, id: b64url.decode(descriptor.id) };
    });
  }

  function prepareCreationOptions(options) {
    const publicKey = getPublicKey(options);
    if (typeof publicKey.challenge !== 'string' || !publicKey.user || typeof publicKey.user.id !== 'string') {
      throw new Error('invalid_webauthn_options');
    }
    const prepared = {
      ...publicKey,
      challenge: b64url.decode(publicKey.challenge),
      user: { ...publicKey.user, id: b64url.decode(publicKey.user.id) },
    };
    const excludeCredentials = decodeDescriptors(publicKey.excludeCredentials);
    if (excludeCredentials) prepared.excludeCredentials = excludeCredentials;
    else delete prepared.excludeCredentials;
    return prepared;
  }

  function prepareRequestOptions(options) {
    const publicKey = getPublicKey(options);
    if (typeof publicKey.challenge !== 'string') throw new Error('invalid_webauthn_options');
    const prepared = { ...publicKey, challenge: b64url.decode(publicKey.challenge) };
    const allowCredentials = decodeDescriptors(publicKey.allowCredentials);
    if (allowCredentials) prepared.allowCredentials = allowCredentials;
    else delete prepared.allowCredentials;
    return prepared;
  }

  function extensionResults(credential) {
    try {
      const results = credential.getClientExtensionResults();
      return results && typeof results === 'object' ? results : {};
    } catch {
      return {};
    }
  }

  function serializeRegistrationCredential(credential) {
    const response = credential.response;
    if (!response || !response.attestationObject || !response.clientDataJSON) {
      throw new Error('incomplete_credential');
    }
    const payload = {
      id: credential.id,
      rawId: b64url.encode(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: b64url.encode(response.attestationObject),
        clientDataJSON: b64url.encode(response.clientDataJSON),
      },
      clientExtensionResults: extensionResults(credential),
    };
    if (typeof response.getTransports === 'function') {
      try {
        const transports = response.getTransports();
        if (Array.isArray(transports) && transports.length) {
          payload.response.transports = transports.filter((item) => typeof item === 'string');
        }
      } catch {
        /* transports are optional */
      }
    }
    return payload;
  }

  function serializeAuthenticationCredential(credential) {
    const response = credential.response;
    if (!response || !response.authenticatorData || !response.clientDataJSON || !response.signature) {
      throw new Error('incomplete_credential');
    }
    let userHandle = null;
    if (response.userHandle && typeof response.userHandle.byteLength === 'number' && response.userHandle.byteLength > 0) {
      userHandle = b64url.encode(response.userHandle);
    }
    return {
      id: credential.id,
      rawId: b64url.encode(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: b64url.encode(response.authenticatorData),
        clientDataJSON: b64url.encode(response.clientDataJSON),
        signature: b64url.encode(response.signature),
        userHandle,
      },
      clientExtensionResults: extensionResults(credential),
    };
  }

  function webauthnFailureMessage(error, context) {
    const name = error && typeof error.name === 'string' ? error.name : '';
    if (name === 'NotAllowedError' || name === 'AbortError') {
      return 'No problem — that was cancelled or timed out. Tap the button again when you’re ready.';
    }
    if (name === 'InvalidStateError') {
      if (context === 'add') {
        return 'This device already has a passkey for your account. Try adding one with a different device or security key.';
      }
      return context === 'create'
        ? 'This device already has a passkey saved for AuthLayer. Try signing in with it instead.'
        : 'Your device couldn’t use that passkey. Please try again.';
    }
    if (name === 'SecurityError') {
      return 'Passkeys need a secure connection. Open AuthLayer over HTTPS (localhost is okay for development).';
    }
    if (name === 'NotSupportedError') {
      return 'This device can’t use passkeys. Try another device or a security key.';
    }
    if (name === 'ConstraintError') {
      return context === 'create'
        ? 'This device couldn’t create a passkey. Try a different device or security key.'
        : 'This device couldn’t use that passkey. Try another device.';
    }
    return null;
  }

  function stepUpErrorFrom(error) {
    if (error instanceof StepUpError) return error;
    if (error instanceof ApiError) {
      if (error.status === 401) {
        return new StepUpError('Your session has ended. Please sign in again.', {
          status: 401,
          unauthorized: true,
        });
      }
      if (error.status === 404 || error.status === 501) {
        return new StepUpError(
          'This server doesn’t support extra confirmation yet. Ask whoever runs it to update AuthLayer.',
          { status: error.status },
        );
      }
      if (error.status === 429) {
        return new StepUpError('Too many confirmation attempts. Please wait a little while and try again.');
      }
      if (error.serverMessage === 'challenge_expired' || error.serverMessage === 'challenge_not_found') {
        return new StepUpError('That confirmation took too long. Please try again.');
      }
      if (error.code === 'webauthn_error') {
        return new StepUpError('We couldn’t confirm it’s you. Please try again.');
      }
      if (error.network) {
        return new StepUpError('We couldn’t reach AuthLayer. Check your connection and try again.');
      }
    }
    return new StepUpError(humanizeError(error, 'We couldn’t confirm it’s you. Please try again.'));
  }

  function performStepUp() {
    if (activeStepUp) return activeStepUp;

    activeStepUp = (async () => {
      try {
        if (state.me && Number(state.me.passkeys) === 0) {
          throw new StepUpError(
            'You need a passkey to confirm this change. Sign out and sign in with an email code to create one.',
          );
        }

        const supportMessage = webauthnSupportMessage();
        if (supportMessage) throw new StepUpError(supportMessage);

        setStepUpStatus(true);

        let start;
        try {
          start = await api(API.stepUpStart, { method: 'POST' });
        } catch (error) {
          throw stepUpErrorFrom(error);
        }

        if (
          !start ||
          typeof start.challenge_id !== 'string' ||
          !start.challenge_id ||
          !start.options
        ) {
          throw new StepUpError('We couldn’t start confirmation. Please try again.');
        }

        let publicKey;
        try {
          publicKey = prepareRequestOptions(start.options);
        } catch {
          throw new StepUpError('We couldn’t prepare confirmation. Please try again.');
        }

        let credential;
        try {
          credential = await navigator.credentials.get({ publicKey });
        } catch (error) {
          const deviceMessage = webauthnFailureMessage(error, 'get');
          throw new StepUpError(deviceMessage || 'We couldn’t confirm it’s you. Please try again.');
        }

        if (!credential) {
          throw new StepUpError('Your device didn’t return a passkey. Please try again.');
        }

        let serialized;
        try {
          serialized = serializeAuthenticationCredential(credential);
        } catch {
          throw new StepUpError('Your device didn’t return a complete passkey. Please try again.');
        }

        let result;
        try {
          result = await api(API.stepUpFinish, {
            method: 'POST',
            body: { challenge_id: start.challenge_id, credential: serialized },
          });
        } catch (error) {
          throw stepUpErrorFrom(error);
        }

        if (!result || result.ok !== true) {
          throw new StepUpError('We couldn’t confirm it’s you. Please try again.');
        }

        return true;
      } finally {
        setStepUpStatus(false);
        activeStepUp = null;
      }
    })();

    return activeStepUp;
  }

  async function withStepUp(action) {
    try {
      return await action();
    } catch (error) {
      if (!isStepUpRequired(error)) throw error;
    }

    try {
      await performStepUp();
    } catch (error) {
      if (error instanceof StepUpError && error.unauthorized) {
        handleSignedOut('Your session has ended. Please sign in again.');
      }
      throw error;
    }

    try {
      return await action();
    } catch (error) {
      if (isStepUpRequired(error)) {
        throw new StepUpError('We still need to confirm it’s you. Please try the action again.');
      }
      throw error;
    }
  }

  function reloadButton() {
    return button('Reload page', {
      kind: 'secondary',
      size: 'sm',
      iconName: 'refresh',
      onClick: () => window.location.reload(),
    });
  }

  function isPasskeyFlow(data) {
    return Boolean(
      data &&
        data.flow === 'passkey' &&
        data.options &&
        typeof data.challenge_id === 'string' &&
        data.challenge_id,
    );
  }

  function isRegistrationFlow(data) {
    return Boolean(
      data &&
        data.flow === 'register_passkey' &&
        data.options &&
        typeof data.challenge_id === 'string' &&
        data.challenge_id,
    );
  }

  function recoverableCodes(data) {
    return Array.isArray(data && data.recovery_codes)
      ? data.recovery_codes.filter((code) => typeof code === 'string' && code.length > 0)
      : [];
  }

  function clearCeremony() {
    state.challengeId = null;
    state.loginOptions = null;
    state.registerOptions = null;
    state.recoveryChallengeId = null;
  }

  function resetAll() {
    state.email = '';
    state.devOutbox = null;
    state.registerReason = 'signin';
    state.pendingCodes = null;
    state.codesContext = 'register';
    state.me = null;
    state.dashboard = null;
    state.dashAlert = null;
    clearCeremony();
  }

  function handleSignedOut(message, kind = 'warning') {
    resetAll();
    renderSignIn({ notice: message ? { kind, message } : null });
  }

  async function recoverExistingSession() {
    try {
      const me = await api(API.me);
      if (me && me.authenticated === true) {
        await loadDashboard({ preloadedMe: me, toast: 'You’re signed in.' });
        return true;
      }
    } catch {
      /* fall through to the caller's error state */
    }
    return false;
  }

  async function refreshFrom(trigger) {
    await withBusy(trigger, 'Refreshing…', trigger.closest('.panel, .dashboard') || app, async () => {
      await loadDashboard({ quiet: true, toast: 'Dashboard updated.', focusId: 'dashboard-title' });
    });
  }

  /* ---------- Shared UI ---------- */

  function authCard({ eyebrow, title, lead, body, footer, notice = null, wide = false }) {
    return h(
      'div',
      { class: 'auth-wrap' },
      h(
        'section',
        {
          class: 'card auth-card' + (wide ? ' card-wide' : ''),
          attrs: { 'aria-labelledby': 'screen-title' },
        },
        notice ? h('div', { class: 'card-alert' }, noticeBanner(notice)) : null,
        eyebrow ? h('p', { class: 'eyebrow' }, eyebrow) : null,
        h('h1', { class: 'screen-title', attrs: { id: 'screen-title', tabindex: '-1' } }, title),
        lead ? h('p', { class: 'lead' }, lead) : null,
        body ? h('div', { class: 'auth-body' }, body) : null,
        footer ? h('div', { class: 'card-footer' }, footer) : null,
      ),
    );
  }

  function devOutboxAlert() {
    if (!state.devOutbox) return null;
    return alertBox(
      'info',
      [
        h('p', null, 'Development mode: no email is actually sent.'),
        h(
          'p',
          { class: 'alert-links' },
          h(
            'a',
            {
              class: 'inline-link',
              attrs: {
                href: state.devOutbox,
                target: '_blank',
                rel: 'noopener noreferrer',
              },
            },
            'Open the dev outbox',
            h('span', { class: 'sr-only' }, ' (opens in a new tab)'),
            icon('external'),
          ),
        ),
      ],
      { iconName: 'mail' },
    );
  }

  function codeField({ id, label, hint, describedBy, recovery = false }) {
    const input = h('input', {
      class: 'input' + (recovery ? ' input-recovery' : ' input-code'),
      attrs: {
        id,
        name: recovery ? 'recovery_code' : 'code',
        type: 'text',
        inputmode: recovery ? 'text' : 'numeric',
        autocomplete: recovery ? 'off' : 'one-time-code',
        autocapitalize: recovery ? 'characters' : 'none',
        spellcheck: 'false',
        maxlength: recovery ? '14' : '6',
        placeholder: recovery ? 'XXXX-XXXX-XXXX' : '000000',
        'aria-describedby': describedBy,
        ...(recovery ? {} : { pattern: '[0-9]*' }),
      },
    });
    return { input, field: h('div', { class: 'field' }, h('label', { class: 'field-label', attrs: { for: id } }, label), input, hint) };
  }

  function supportList(items) {
    return h(
      'ul',
      { class: 'support-list' },
      items.map((text) =>
        h(
          'li',
          null,
          h('span', { class: 'support-check' }, icon('check')),
          h('span', null, text),
        ),
      ),
    );
  }

  /* ---------- Sign-in screens ---------- */

  function renderSignIn({ notice = null, email = state.email, error = '' } = {}) {
    clearCeremony();
    state.pendingCodes = null;
    let card = null;

    const errorBox = liveError('signin-error');
    if (error) setLiveError(errorBox, error);

    const input = h('input', {
      class: 'input',
      attrs: {
        id: 'email',
        name: 'email',
        type: 'email',
        autocomplete: 'email',
        inputmode: 'email',
        autocapitalize: 'none',
        spellcheck: 'false',
        placeholder: 'you@example.com',
        required: true,
        'aria-describedby': 'signin-error',
      },
    });
    input.value = email || '';

    const submitBtn = button('Continue with email', { kind: 'primary', type: 'submit', block: true });

    const form = h(
      'form',
      {
        class: 'form',
        attrs: { novalidate: true, 'aria-describedby': 'signin-error' },
        on: { submit },
      },
      h(
        'div',
        { class: 'field' },
        h('label', { class: 'field-label', attrs: { for: 'email' } }, 'Email address'),
        input,
      ),
      errorBox,
      submitBtn,
    );

    input.addEventListener('input', () => {
      input.removeAttribute('aria-invalid');
      setLiveError(errorBox, null);
    });

    async function submit(event) {
      event.preventDefault();
      if (card && card.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);
      const value = input.value.trim();

      if (!isValidEmail(value)) {
        input.setAttribute('aria-invalid', 'true');
        setLiveError(errorBox, 'Enter a valid email address, like you@example.com.');
        input.focus();
        return;
      }

      await withBusy(submitBtn, 'Sending code…', card, async () => {
        try {
          const data = await api(API.start, { method: 'POST', body: { email: value } });
          state.email = emailFrom(data, value);
          state.devOutbox = safeInternalPath(data.dev_outbox);

          if (isPasskeyFlow(data)) {
            enterPasskeySignIn(data);
          } else if (data.flow === 'code') {
            state.loginOptions = null;
            state.challengeId = null;
            renderCodeScreen();
          } else {
            setLiveError(errorBox, 'Something unexpected happened. Please try again.');
          }
        } catch (error) {
          if (error instanceof ApiError && error.serverMessage === 'invalid_email') {
            input.setAttribute('aria-invalid', 'true');
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t send your sign-in email. Please try again.'));
        }
      });
    }

    const wrap = authCard({
      notice,
      eyebrow: 'Sign in',
      title: 'Welcome back',
      lead: 'Enter your email and we’ll send you a one-time code. No password needed.',
      body: form,
      footer: h(
        'div',
        { class: 'link-row' },
        h('span', null, 'Lost your device?'),
        h(
          'button',
          {
            class: 'text-button',
            attrs: { type: 'button' },
            on: {
              click: () => {
                const typed = input.value.trim();
                if (typed.includes('@')) state.email = typed;
                renderRecoveryEmail();
              },
            },
          },
          'Use a recovery code',
        ),
      ),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function enterPasskeySignIn(data, options = {}) {
    state.loginOptions = data.options;
    state.challengeId = data.challenge_id;
    state.registerOptions = null;
    state.recoveryChallengeId = null;
    state.registerReason = 'signin';
    renderPasskeySignIn(options);
  }

  function enterRegistration(data, reason) {
    state.registerOptions = data.options;
    state.challengeId = data.challenge_id;
    state.registerReason = reason;
    state.loginOptions = null;
    state.recoveryChallengeId = null;
    renderRegisterPasskey();
  }

  async function checkForPasskey(trigger, scope, errorBox) {
    if (scope && scope.getAttribute('aria-busy') === 'true') return;
    await withBusy(trigger, 'Checking…', scope, async () => {
      setLiveError(errorBox, null);
      try {
        const data = await api(API.start, { method: 'POST', body: { email: state.email } });
        state.email = emailFrom(data, state.email);
        state.devOutbox = safeInternalPath(data.dev_outbox);
        if (isPasskeyFlow(data)) {
          enterPasskeySignIn(data);
        } else if (data.flow === 'code') {
          clearCeremony();
          renderCodeScreen({
            notice: {
              kind: 'info',
              message:
                'No passkey is set up for this email yet. A fresh code has been sent — use the newest one in your email.',
            },
          });
        } else {
          setLiveError(errorBox, 'Something unexpected happened. Please try again.');
        }
      } catch (error) {
        setLiveError(errorBox, humanizeError(error, 'We couldn’t check for a passkey. Please try again.'));
      }
    });
  }

  function renderCodeScreen({ notice = null, error = '' } = {}) {
    if (!state.email) {
      renderSignIn();
      return;
    }
    let card = null;
    const errorBox = liveError('code-error');
    if (error) setLiveError(errorBox, error);

    const { input, field } = codeField({
      id: 'code',
      label: '6-digit code',
      hint: null,
      describedBy: 'code-hint code-error',
    });

    const submitBtn = button('Verify code', { kind: 'primary', type: 'submit', block: true });
    const resendBtn = h(
      'button',
      {
        class: 'text-button',
        attrs: { type: 'button' },
        on: { click: () => resend(resendBtn) },
      },
      'Send a new code',
    );
    const passkeyBtn = h(
      'button',
      {
        class: 'text-button',
        attrs: { type: 'button' },
        on: { click: () => checkForPasskey(passkeyBtn, card, errorBox) },
      },
      'Use a passkey instead',
    );
    const recoveryBtn = h(
      'button',
      {
        class: 'text-button',
        attrs: { type: 'button' },
        on: {
          click: () => {
            clearCeremony();
            renderRecoveryEmail();
          },
        },
      },
      'Use a recovery code',
    );
    const backBtn = button('Use a different email', {
      kind: 'ghost',
      size: 'sm',
      iconName: 'arrowLeft',
      className: 'back-link',
      onClick: () => renderSignIn(),
    });

    const form = h(
      'form',
      {
        class: 'form',
        attrs: { novalidate: true, 'aria-describedby': 'code-error' },
        on: { submit },
      },
      field,
      h(
        'div',
        { class: 'hint-row' },
        h('p', { class: 'field-hint', attrs: { id: 'code-hint' } }, 'The code works once and expires shortly.'),
        resendBtn,
      ),
      errorBox,
      submitBtn,
    );

    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
      input.removeAttribute('aria-invalid');
      setLiveError(errorBox, null);
    });

    async function submit(event) {
      event.preventDefault();
      if (card && card.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);
      const code = input.value.replace(/\D/g, '').slice(0, 6);
      input.value = code;
      if (code.length !== 6) {
        input.setAttribute('aria-invalid', 'true');
        setLiveError(errorBox, 'Enter the 6-digit code from your email.');
        input.focus();
        return;
      }

      await withBusy(submitBtn, 'Checking code…', card, async () => {
        try {
          const data = await api(API.verifyCode, {
            method: 'POST',
            body: { email: state.email, code },
          });
          if (isRegistrationFlow(data)) {
            enterRegistration(data, 'signin');
          } else {
            setLiveError(errorBox, 'Something unexpected happened. Please try again.');
          }
        } catch (error) {
          input.setAttribute('aria-invalid', 'true');
          if (error instanceof ApiError && error.serverMessage === 'use_passkey') {
            const action = button('Use my passkey', {
              kind: 'secondary',
              size: 'sm',
              onClick: () => checkForPasskey(action, card, errorBox),
            });
            setLiveError(
              errorBox,
              'This account is protected with a passkey. Use your passkey to sign in.',
              action,
            );
          } else {
            setLiveError(errorBox, humanizeError(error, 'We couldn’t verify that code. Please try again.'));
          }
        }
      });
    }

    async function resend(trigger) {
      if (card && card.getAttribute('aria-busy') === 'true') return;
      await withBusy(trigger, 'Sending…', card, async () => {
        setLiveError(errorBox, null);
        try {
          const data = await api(API.start, { method: 'POST', body: { email: state.email } });
          state.email = emailFrom(data, state.email);
          state.devOutbox = safeInternalPath(data.dev_outbox);
          if (isPasskeyFlow(data)) {
            enterPasskeySignIn(data);
          } else if (data.flow === 'code') {
            renderCodeScreen({
              notice: { kind: 'info', message: 'A fresh code is on its way. Use the newest code in your email.' },
            });
          } else {
            setLiveError(errorBox, 'Something unexpected happened. Please try again.');
          }
        } catch (error) {
          setLiveError(errorBox, humanizeError(error, 'We couldn’t send a new code. Please try again.'));
        }
      });
    }

    const devBox = devOutboxAlert();
    const wrap = authCard({
      notice,
      eyebrow: 'Check your email',
      title: 'Enter your sign-in code',
      lead: ['We sent a 6-digit code to ', h('strong', { class: 'email-text' }, state.email), '.'],
      body: [backBtn, devBox, form],
      footer: h('div', { class: 'link-row' }, passkeyBtn, h('span', { class: 'dot-sep', attrs: { 'aria-hidden': 'true' } }, '•'), recoveryBtn),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function renderPasskeySignIn({ notice = null, error = '', stale = false } = {}) {
    if (!state.email) {
      renderSignIn();
      return;
    }
    if (!stale && (!state.loginOptions || !state.challengeId)) stale = true;

    const supportMessage = webauthnSupportMessage();
    let card = null;
    const errorBox = liveError('passkey-signin-error');
    if (error) setLiveError(errorBox, error);
    if (stale && !error) {
      setLiveError(errorBox, 'That sign-in attempt has ended. Tap “Try again” for a fresh prompt.');
    }

    let primary = null;

    async function attempt() {
      if (card && card.getAttribute('aria-busy') === 'true') return;
      if (stale) {
        await restart();
        return;
      }
      await withBusy(primary, 'Waiting for your device…', card, async () => {
        setLiveError(errorBox, null);
        let publicKey;
        try {
          publicKey = prepareRequestOptions(state.loginOptions);
        } catch {
          state.loginOptions = null;
          state.challengeId = null;
          renderPasskeySignIn({
            stale: true,
            error: 'We couldn’t prepare your passkey request. Please try again.',
          });
          return;
        }

        try {
          const credential = await navigator.credentials.get({ publicKey });
          if (!credential) {
            setLiveError(errorBox, 'Your device didn’t return a passkey. Please try again.');
            return;
          }
          const serialized = serializeAuthenticationCredential(credential);
          await api(API.passkeyLogin, {
            method: 'POST',
            body: { challenge_id: state.challengeId, credential: serialized },
          });
          state.loginOptions = null;
          state.challengeId = null;
          await loadDashboard({ toast: 'Signed in with your passkey.' });
        } catch (error) {
          const deviceMessage = webauthnFailureMessage(error, 'get');
          if (deviceMessage) {
            setLiveError(errorBox, deviceMessage);
            return;
          }
          if (error instanceof ApiError) {
            if (error.network) {
              if (await recoverExistingSession()) return;
              setLiveError(
                errorBox,
                'We couldn’t confirm that sign-in. Check your connection and try again.',
                reloadButton(),
              );
              return;
            }
            state.loginOptions = null;
            state.challengeId = null;
            renderPasskeySignIn({
              stale: true,
              error: humanizeError(error, 'We couldn’t sign you in with that passkey. Please try again.'),
            });
            return;
          }
          setLiveError(errorBox, 'We couldn’t sign you in with that passkey. Please try again.');
        }
      });
    }

    async function restart() {
      await withBusy(primary, 'Getting ready…', card, async () => {
        setLiveError(errorBox, null);
        try {
          const data = await api(API.start, { method: 'POST', body: { email: state.email } });
          state.email = emailFrom(data, state.email);
          state.devOutbox = safeInternalPath(data.dev_outbox);
          if (isPasskeyFlow(data)) {
            enterPasskeySignIn(data, {
              notice: { kind: 'info', message: 'Ready — tap “Sign in with passkey” again.' },
            });
          } else if (data.flow === 'code') {
            clearCeremony();
            renderCodeScreen({
              notice: {
                kind: 'info',
                message: 'Your account no longer has a passkey. Use the emailed code instead.',
              },
            });
          } else {
            setLiveError(errorBox, 'Something unexpected happened. Please try again.');
          }
        } catch (error) {
          setLiveError(errorBox, humanizeError(error, 'We couldn’t get a fresh passkey prompt. Please try again.'));
        }
      });
    }

    if (!supportMessage) {
      primary = button(stale ? 'Try again' : 'Sign in with passkey', {
        kind: 'primary',
        block: true,
        iconName: stale ? 'refresh' : 'key',
        onClick: attempt,
      });
    }

    const recoveryButton = button('Use a recovery code', {
      kind: supportMessage ? 'primary' : 'secondary',
      block: supportMessage,
      iconName: 'shield',
      onClick: () => {
        clearCeremony();
        renderRecoveryEmail();
      },
    });

    const diffEmail = h(
      'button',
      {
        class: 'text-button',
        attrs: { type: 'button' },
        on: { click: () => renderSignIn() },
      },
      'Use a different email',
    );

    const body = [];
    if (supportMessage) {
      body.push(alertBox('warning', h('p', null, supportMessage)));
    }
    body.push(errorBox);
    if (supportMessage) {
      body.push(recoveryButton);
    } else {
      body.push(primary);
    }

    const footerLinks = [];
    if (!supportMessage) {
      footerLinks.push(
        h(
          'button',
          {
            class: 'text-button',
            attrs: { type: 'button' },
            on: {
              click: () => {
                clearCeremony();
                renderRecoveryEmail();
              },
            },
          },
          'Use a recovery code',
        ),
        h('span', { class: 'dot-sep', attrs: { 'aria-hidden': 'true' } }, '•'),
      );
    }
    footerLinks.push(diffEmail);

    const wrap = authCard({
      notice,
      eyebrow: 'Passkey sign-in',
      title: 'Welcome back',
      lead: [
        'Sign in as ',
        h('strong', { class: 'email-text' }, state.email),
        ' with your passkey. You’ll confirm with your fingerprint, face, or screen lock.',
      ],
      body,
      footer: h('div', { class: 'link-row' }, footerLinks),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function renderRegisterPasskey({ notice = null, error = '', stale = false } = {}) {
    const supportMessage = webauthnSupportMessage();
    if (!state.registerOptions || !state.challengeId) stale = true;
    if (supportMessage) stale = true;
    const reason = state.registerReason === 'recovery' ? 'recovery' : 'signin';

    let card = null;
    const errorBox = liveError('register-passkey-error');
    if (error) setLiveError(errorBox, error);
    if (stale && !error && !supportMessage) {
      setLiveError(errorBox, 'This setup step has expired. Please start again.');
    }

    let primary = null;

    async function createPasskey() {
      if (card && card.getAttribute('aria-busy') === 'true') return;
      await withBusy(primary, 'Waiting for your device…', card, async () => {
        setLiveError(errorBox, null);
        try {
          const publicKey = prepareCreationOptions(state.registerOptions);
          const credential = await navigator.credentials.create({ publicKey });
          if (!credential) {
            setLiveError(errorBox, 'Your device didn’t return a passkey. Please try again.');
            return;
          }
          const serialized = serializeRegistrationCredential(credential);
          const data = await api(API.passkeyRegister, {
            method: 'POST',
            body: { challenge_id: state.challengeId, credential: serialized },
          });
          await handleRegistrationSuccess(data);
        } catch (error) {
          if (error && error.message === 'invalid_webauthn_options') {
            state.registerOptions = null;
            state.challengeId = null;
            renderRegisterPasskey({
              stale: true,
              error: 'Something went wrong preparing your passkey. Please start again.',
            });
            return;
          }
          if (error && error.message === 'incomplete_credential') {
            setLiveError(errorBox, 'Your device didn’t return a complete passkey. Please try again.');
            return;
          }
          const deviceMessage = webauthnFailureMessage(error, 'create');
          if (deviceMessage) {
            setLiveError(errorBox, deviceMessage);
            return;
          }
          if (error instanceof ApiError) {
            if (error.network) {
              if (await recoverExistingSession()) return;
              setLiveError(
                errorBox,
                'We couldn’t confirm that your passkey was saved. Reload this page to check.',
                reloadButton(),
              );
              return;
            }
            state.registerOptions = null;
            state.challengeId = null;
            renderRegisterPasskey({
              stale: true,
              error: humanizeError(error, 'We couldn’t finish saving your passkey. Please start again.'),
            });
            return;
          }
          setLiveError(
            errorBox,
            'We couldn’t create a passkey on this device. Please try again or use a different device.',
          );
        }
      });
    }

    function startOver() {
      clearCeremony();
      if (reason === 'recovery') renderRecoveryEmail();
      else renderSignIn();
    }

    if (!stale) {
      primary = button('Create my passkey', {
        kind: 'primary',
        block: true,
        iconName: 'key',
        onClick: createPasskey,
      });
    } else {
      primary = button('Start over', {
        kind: 'primary',
        block: true,
        iconName: 'refresh',
        onClick: startOver,
      });
    }

    const body = [];
    if (stale && reason === 'recovery') {
      body.push(
        alertBox(
          'info',
          h('p', null, 'You’ve verified your email. Create a new passkey to finish recovering your account.'),
        ),
      );
    }
    if (!stale) {
      body.push(
        supportList([
          'Nothing to remember — your device holds the key.',
          'It can’t be guessed or reused, even in a data breach.',
          'Works with Face ID, Touch ID, Windows Hello, or a security key.',
        ]),
      );
    }
    if (supportMessage) {
      body.push(alertBox('warning', h('p', null, supportMessage)));
    }
    body.push(errorBox, primary);

    const wrap = authCard({
      notice,
      eyebrow: reason === 'recovery' ? 'Account recovery' : 'One last step',
      title: reason === 'recovery' ? 'Create a new passkey' : 'Create your passkey',
      lead:
        reason === 'recovery'
          ? 'Set up a passkey on this device to finish getting back into your account.'
          : 'A passkey lets you sign in with your fingerprint, face, or screen lock. There’s no password to remember.',
      body,
      footer: !stale
        ? h(
            'div',
            { class: 'link-row' },
            h(
              'button',
              {
                class: 'text-button',
                attrs: { type: 'button' },
                on: { click: startOver },
              },
              'Cancel and start over',
            ),
          )
        : null,
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  async function handleRegistrationSuccess(data) {
    const codes = recoverableCodes(data);
    state.registerOptions = null;
    state.challengeId = null;
    const wasRecovery = state.registerReason === 'recovery';
    state.registerReason = 'signin';

    if (codes.length) {
      state.pendingCodes = codes;
      state.codesContext = wasRecovery ? 'recovery' : 'register';
      renderRecoveryCodes();
    } else {
      await loadDashboard({ toast: 'Your passkey is ready.' });
    }
  }

  /* ---------- Recovery screens ---------- */

  function renderRecoveryEmail({ notice = null, email = state.email } = {}) {
    clearCeremony();
    state.pendingCodes = null;
    let card = null;

    const errorBox = liveError('recovery-email-error');
    const input = h('input', {
      class: 'input',
      attrs: {
        id: 'recovery-email',
        name: 'email',
        type: 'email',
        autocomplete: 'email',
        inputmode: 'email',
        autocapitalize: 'none',
        spellcheck: 'false',
        placeholder: 'you@example.com',
        required: true,
        'aria-describedby': 'recovery-email-error',
      },
    });
    input.value = email || '';
    const submitBtn = button('Send recovery code', { kind: 'primary', type: 'submit', block: true });

    const form = h(
      'form',
      {
        class: 'form',
        attrs: { novalidate: true, 'aria-describedby': 'recovery-email-error' },
        on: { submit },
      },
      h(
        'div',
        { class: 'field' },
        h('label', { class: 'field-label', attrs: { for: 'recovery-email' } }, 'Email address'),
        input,
      ),
      errorBox,
      submitBtn,
    );

    input.addEventListener('input', () => {
      input.removeAttribute('aria-invalid');
      setLiveError(errorBox, null);
    });

    async function submit(event) {
      event.preventDefault();
      if (card && card.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);
      const value = input.value.trim();
      if (!isValidEmail(value)) {
        input.setAttribute('aria-invalid', 'true');
        setLiveError(errorBox, 'Enter the email address on your account.');
        input.focus();
        return;
      }

      await withBusy(submitBtn, 'Sending code…', card, async () => {
        try {
          const data = await api(API.recoverStart, { method: 'POST', body: { email: value } });
          state.email = emailFrom(data, value);
          state.devOutbox = safeInternalPath(data.dev_outbox);
          state.recoveryChallengeId = null;
          renderRecoveryEmailCode();
        } catch (error) {
          if (error instanceof ApiError && error.serverMessage === 'invalid_email') {
            input.setAttribute('aria-invalid', 'true');
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t start recovery. Please try again.'));
        }
      });
    }

    const wrap = authCard({
      notice,
      eyebrow: 'Account recovery',
      title: 'Recover your account',
      lead: 'Enter the email on your account. We’ll send a code to prove it’s you, then you can use a recovery code to set up a new passkey.',
      body: form,
      footer: h(
        'div',
        { class: 'link-row' },
        h(
          'button',
          {
            class: 'text-button',
            attrs: { type: 'button' },
            on: { click: () => renderSignIn() },
          },
          'Back to sign in',
        ),
        h('span', { class: 'dot-sep', attrs: { 'aria-hidden': 'true' } }, '•'),
        h('span', null, 'Keep your recovery codes nearby.'),
      ),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function renderRecoveryEmailCode({ notice = null, error = '' } = {}) {
    if (!state.email) {
      renderRecoveryEmail();
      return;
    }
    let card = null;
    const errorBox = liveError('recovery-code-error');
    if (error) setLiveError(errorBox, error);

    const { input, field } = codeField({
      id: 'recovery-email-code',
      label: '6-digit code',
      hint: null,
      describedBy: 'recovery-email-code-hint recovery-code-error',
    });
    const submitBtn = button('Continue', { kind: 'primary', type: 'submit', block: true });
    const resendBtn = h(
      'button',
      {
        class: 'text-button',
        attrs: { type: 'button' },
        on: { click: () => resend(resendBtn) },
      },
      'Send a new code',
    );
    const backBtn = button('Use a different email', {
      kind: 'ghost',
      size: 'sm',
      iconName: 'arrowLeft',
      className: 'back-link',
      onClick: () => renderRecoveryEmail(),
    });

    const form = h(
      'form',
      {
        class: 'form',
        attrs: { novalidate: true, 'aria-describedby': 'recovery-code-error' },
        on: { submit },
      },
      field,
      h(
        'div',
        { class: 'hint-row' },
        h(
          'p',
          { class: 'field-hint', attrs: { id: 'recovery-email-code-hint' } },
          'The code works once and expires shortly.',
        ),
        resendBtn,
      ),
      errorBox,
      submitBtn,
    );

    input.addEventListener('input', () => {
      input.value = input.value.replace(/\D/g, '').slice(0, 6);
      input.removeAttribute('aria-invalid');
      setLiveError(errorBox, null);
    });

    async function submit(event) {
      event.preventDefault();
      if (card && card.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);
      const code = input.value.replace(/\D/g, '').slice(0, 6);
      input.value = code;
      if (code.length !== 6) {
        input.setAttribute('aria-invalid', 'true');
        setLiveError(errorBox, 'Enter the 6-digit code from your email.');
        input.focus();
        return;
      }

      await withBusy(submitBtn, 'Checking code…', card, async () => {
        try {
          const data = await api(API.recoverVerifyEmail, {
            method: 'POST',
            body: { email: state.email, code },
          });
          if (data.flow === 'recovery_code' && typeof data.challenge_id === 'string' && data.challenge_id) {
            state.recoveryChallengeId = data.challenge_id;
            renderRecoveryCode();
          } else {
            setLiveError(errorBox, 'Something unexpected happened. Please try again.');
          }
        } catch (error) {
          input.setAttribute('aria-invalid', 'true');
          setLiveError(errorBox, humanizeError(error, 'We couldn’t verify that code. Please try again.'));
        }
      });
    }

    async function resend(trigger) {
      if (card && card.getAttribute('aria-busy') === 'true') return;
      await withBusy(trigger, 'Sending…', card, async () => {
        setLiveError(errorBox, null);
        try {
          const data = await api(API.recoverStart, { method: 'POST', body: { email: state.email } });
          state.email = emailFrom(data, state.email);
          state.devOutbox = safeInternalPath(data.dev_outbox);
          renderRecoveryEmailCode({
            notice: { kind: 'info', message: 'A fresh code is on its way. Use the newest code in your email.' },
          });
        } catch (error) {
          setLiveError(errorBox, humanizeError(error, 'We couldn’t send a new code. Please try again.'));
        }
      });
    }

    const devBox = devOutboxAlert();
    const wrap = authCard({
      notice,
      eyebrow: 'Account recovery',
      title: 'Enter your email code',
      lead: ['We sent a 6-digit code to ', h('strong', { class: 'email-text' }, state.email), '.'],
      body: [backBtn, devBox, form],
      footer: h('div', { class: 'link-row' }, h('span', null, 'Next, you’ll enter one of your saved recovery codes.')),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function renderRecoveryCode({ error = '', stale = false } = {}) {
    if (!stale && !state.recoveryChallengeId) {
      renderRecoveryEmail();
      return;
    }
    let card = null;
    const errorBox = liveError('recovery-enter-error');
    if (error) setLiveError(errorBox, error);

    async function submit(event) {
      event.preventDefault();
      if (card && card.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);
      const code = input.value.trim();
      if (!code) {
        input.setAttribute('aria-invalid', 'true');
        setLiveError(errorBox, 'Enter one of your saved recovery codes.');
        input.focus();
        return;
      }

      await withBusy(submitBtn, 'Checking code…', card, async () => {
        try {
          const data = await api(API.recoverVerifyCode, {
            method: 'POST',
            body: { challenge_id: state.recoveryChallengeId, recovery_code: code },
          });
          if (isRegistrationFlow(data)) {
            state.recoveryChallengeId = null;
            enterRegistration(data, 'recovery');
          } else {
            state.recoveryChallengeId = null;
            renderRecoveryCode({
              stale: true,
              error: 'Something unexpected happened. Please start recovery again.',
            });
          }
        } catch (error) {
          const message =
            error instanceof ApiError && error.serverMessage === 'invalid_recovery_code'
              ? 'That recovery code didn’t work. For your security, please start recovery again.'
              : humanizeError(error, 'We couldn’t verify that recovery code. Please start recovery again.');
          state.recoveryChallengeId = null;
          renderRecoveryCode({ stale: true, error: message });
        }
      });
    }

    function startOver() {
      clearCeremony();
      renderRecoveryEmail();
    }

    const body = [];
    let submitBtn = null;
    let input = null;

    if (stale) {
      body.push(errorBox);
      body.push(
        button('Start recovery again', {
          kind: 'primary',
          block: true,
          iconName: 'refresh',
          onClick: startOver,
        }),
      );
    } else {
      const field = codeField({
        id: 'recovery-code',
        label: 'Recovery code',
        hint: h(
          'p',
          { class: 'field-hint', attrs: { id: 'recovery-code-hint' } },
          'Each code works once. Hyphens are optional.',
        ),
        describedBy: 'recovery-code-hint recovery-enter-error',
        recovery: true,
      });
      input = field.input;
      submitBtn = button('Verify recovery code', { kind: 'primary', type: 'submit', block: true });

      input.addEventListener('input', () => {
        const caret = input.selectionStart;
        const before = input.value
          .slice(0, caret)
          .toUpperCase()
          .replace(/[^A-Z0-9_-]/g, '')
          .replace(/-/g, '').length;
        input.value = formatRecoveryInput(input.value);
        const caretPosition = Math.min(
          input.value.length,
          before + (before > 0 ? Math.floor((before - 1) / 4) : 0),
        );
        try {
          input.setSelectionRange(caretPosition, caretPosition);
        } catch {
          /* not all input types expose a selection */
        }
        input.removeAttribute('aria-invalid');
        setLiveError(errorBox, null);
      });

      const form = h(
        'form',
        {
          class: 'form',
          attrs: { novalidate: true, 'aria-describedby': 'recovery-enter-error' },
          on: { submit },
        },
        field.field,
        errorBox,
        submitBtn,
      );
      body.push(form);
    }

    const footerLinks = [];
    if (!stale) {
      footerLinks.push(
        h(
          'button',
          {
            class: 'text-button',
            attrs: { type: 'button' },
            on: { click: startOver },
          },
          'Start over',
        ),
        h('span', { class: 'dot-sep', attrs: { 'aria-hidden': 'true' } }, '•'),
      );
    }
    footerLinks.push(
      h(
        'button',
        {
          class: 'text-button',
          attrs: { type: 'button' },
          on: { click: () => renderSignIn() },
        },
        'Back to sign in',
      ),
    );

    const wrap = authCard({
      eyebrow: 'Account recovery',
      title: 'Use a recovery code',
      lead: 'Type one of the recovery codes you saved. Each code works once and can only be used by you.',
      body,
      footer: h('div', { class: 'link-row' }, footerLinks),
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  function renderRecoveryCodes() {
    const codes = recoverableCodes({ recovery_codes: state.pendingCodes });
    if (!codes.length) {
      state.pendingCodes = null;
      loadDashboard({});
      return;
    }
    state.pendingCodes = codes;

    const context = state.codesContext;
    const lead =
      context === 'recovery'
        ? 'Your recovery code was accepted and your new passkey is ready. Save this new set of codes for next time.'
        : context === 'regenerate'
          ? 'Your old codes no longer work. Save this new set somewhere safe.'
          : 'You’re all set. Save these codes so you can get back in if you ever lose your device.';

    let card = null;
    const errorBox = liveError('recovery-codes-error');

    const copyBtn = button('Copy all codes', {
      kind: 'secondary',
      block: true,
      iconName: 'copy',
      onClick: async () => {
        const copied = await copyText(codes.join('\n'));
        if (copied) {
          flashButtonLabel(copyBtn, 'Copied');
          showToast('Recovery codes copied to your clipboard.');
        } else {
          setLiveError(
            errorBox,
            'Copying didn’t work in this browser. Select the codes above and copy them manually.',
          );
        }
      },
    });

    const continueBtn = button('I’ve saved them — continue', {
      kind: 'primary',
      block: true,
      iconName: 'check',
      onClick: async () => {
        if (card && card.getAttribute('aria-busy') === 'true') return;
        state.pendingCodes = null;
        await withBusy(continueBtn, 'Opening your account…', card, async () => {
          await loadDashboard({
            toast: context === 'regenerate' ? 'Recovery codes updated.' : 'You’re all set.',
          });
        });
      },
    });

    const list = h(
      'ol',
      { class: 'codes-grid', attrs: { 'aria-label': 'Your recovery codes' } },
      codes.map((code) => h('li', { class: 'code-chip' }, code)),
    );

    const body = h(
      'div',
      { class: 'codes-body' },
      alertBox(
        'warning',
        [
          h('p', { class: 'alert-strong' }, 'These codes are shown only once.'),
          h('p', null, 'Store them somewhere safe and private. Anyone who has a code can get into your account.'),
        ],
        { iconName: 'alert' },
      ),
      list,
      errorBox,
      h('div', { class: 'codes-actions' }, copyBtn, continueBtn),
      h(
        'p',
        { class: 'codes-note' },
        'Each code works once. You can generate a new set from your dashboard whenever you need to.',
      ),
    );

    const wrap = authCard({
      eyebrow: 'Recovery codes',
      title: 'Save your recovery codes',
      lead,
      body,
      wide: true,
    });

    card = wrap.querySelector('.auth-card');
    mount(wrap);
  }

  /* ---------- Dashboard ---------- */

  function statTile(iconName, value, label, sub, small = false) {
    return h(
      'div',
      { class: 'stat' },
      h('div', { class: 'stat-icon' }, icon(iconName)),
      h('p', { class: `stat-value${small ? ' stat-value-date' : ''}` }, value),
      h('span', { class: 'stat-label' }, label),
      sub ? h('span', { class: 'stat-sub' }, sub) : null,
    );
  }

  function panel({ id, iconName, title, subtitle, action = null, content }) {
    return h(
      'section',
      { class: 'panel', attrs: { 'aria-labelledby': id } },
      h(
        'div',
        { class: 'panel-head' },
        h('div', { class: 'panel-icon' }, icon(iconName)),
        h(
          'div',
          { class: 'panel-titles' },
          h('h2', { class: 'panel-title', attrs: { id, tabindex: '-1' } }, title),
          h('p', { class: 'panel-sub' }, subtitle),
        ),
        action ? h('div', { class: 'panel-action' }, action) : null,
      ),
      h('div', { class: 'panel-body' }, content),
    );
  }

  async function loadDashboard({
    preloadedMe = null,
    notice = null,
    toast = null,
    focusId = null,
    quiet = false,
    signedOutMessage = 'Your session has ended. Please sign in again.',
    signedOutKind = 'warning',
  } = {}) {
    let me = preloadedMe;
    try {
      if (!me) me = await api(API.me);
      if (!me || me.authenticated !== true || !me.user) {
        handleSignedOut(signedOutMessage, signedOutKind);
        return;
      }
      state.me = me;

      const results = await Promise.allSettled([api(API.passkeys), api(API.sessions)]);
      const [passkeyResult, sessionResult] = results;
      if (unauthorizedResult(passkeyResult) || unauthorizedResult(sessionResult)) {
        handleSignedOut(signedOutMessage, signedOutKind);
        return;
      }

      const passkeys =
        passkeyResult.status === 'fulfilled' && Array.isArray(passkeyResult.value.passkeys)
          ? passkeyResult.value.passkeys.filter((item) => item && typeof item.id === 'string')
          : [];
      const sessions =
        sessionResult.status === 'fulfilled' && Array.isArray(sessionResult.value.sessions)
          ? sessionResult.value.sessions.filter((item) => item && typeof item.id === 'string')
          : [];

      state.dashboard = {
        passkeys,
        sessions,
        passkeysError:
          passkeyResult.status === 'rejected'
            ? humanizeError(passkeyResult.reason, 'We couldn’t load your passkeys right now.')
            : null,
        sessionsError:
          sessionResult.status === 'rejected'
            ? humanizeError(sessionResult.reason, 'We couldn’t load your sessions right now.')
            : null,
      };
      state.dashAlert = null;
      renderDashboard({ notice, focusId });
      if (toast) showToast(toast);
    } catch (error) {
      if (isUnauthorizedError(error)) {
        handleSignedOut(signedOutMessage, signedOutKind);
        return;
      }
      if (quiet && state.me && state.dashboard) {
        state.dashAlert = humanizeError(error, 'We couldn’t refresh your account. Please try again.');
        renderDashboard();
        return;
      }
      renderFatal(error);
    }
  }

  function buildPasskeyItem(passkey) {
    const label = typeof passkey.label === 'string' && passkey.label.trim() ? passkey.label.trim() : 'Passkey';
    const errorBox = liveError();
    errorBox.classList.add('item-error');
    let removeButton = null;

    const item = h(
      'li',
      { class: 'list-item' },
      h('div', { class: 'item-icon' }, icon('key')),
      h(
        'div',
        { class: 'item-main' },
        h('div', { class: 'item-title-row' }, h('span', { class: 'item-title' }, label)),
        h(
          'p',
          { class: 'item-meta' },
          'Added ',
          dateSpan(passkey.created_at),
          ' · Last used ',
          passkey.last_used_at ? dateSpan(passkey.last_used_at, { withTime: true }) : 'not yet',
        ),
      ),
      h(
        'div',
        { class: 'item-actions' },
        (removeButton = button('Remove', {
          kind: 'danger',
          size: 'sm',
          iconName: 'trash',
          onClick: removePasskey,
        })),
      ),
      errorBox,
    );

    async function removePasskey() {
      const passkeyCount = Number(state.me && state.me.passkeys);
      const recoveryCount = Number(state.me && state.me.recovery_codes_remaining);
      let message = `You won’t be able to use “${label}” to sign in anymore. This can’t be undone.`;
      if (passkeyCount <= 1 && recoveryCount === 0) {
        message += ' This is your only way to sign in, so it can’t be removed until you have recovery codes.';
      }
      message += ' If this browser is using this passkey, it will be signed out.';

      const confirmed = await confirmDialog({
        title: 'Remove this passkey?',
        message,
        confirmLabel: 'Remove passkey',
        danger: true,
      });
      if (!confirmed) return;

      setLiveError(errorBox, null);
      await withBusy(removeButton, 'Removing…', item, async () => {
        try {
          await withStepUp(() =>
            api(`/api/passkeys/${encodeURIComponent(passkey.id)}/revoke`, { method: 'POST' }),
          );
          await loadDashboard({
            quiet: true,
            toast: 'Passkey removed.',
            focusId: 'passkeys-heading',
            signedOutMessage:
              'That passkey was removed. This browser was signed out because it was using that passkey.',
            signedOutKind: 'info',
          });
        } catch (error) {
          if (error instanceof StepUpError) {
            setLiveError(errorBox, error.userMessage);
            return;
          }
          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }
          if (error instanceof ApiError && error.status === 404) {
            setLiveError(errorBox, 'That passkey is no longer on your account. Refresh the page to update the list.');
            return;
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t remove that passkey. Please try again.'));
        }
      });
    }

    return item;
  }

  function buildSessionItem(session) {
    const current = session.current === true;
    const device = describeUserAgent(session.user_agent);
    const errorBox = liveError();
    errorBox.classList.add('item-error');
    let revokeButton = null;

    const metaParts = [];
    if (current) {
      metaParts.push(h('span', { class: 'meta-strong' }, device), ' · ');
    }
    metaParts.push(
      'Signed in ',
      dateSpan(session.created_at),
      ' · Last active ',
      relativeSpan(session.last_seen_at),
      ' · Expires ',
      dateSpan(session.expires_at),
    );
    if (typeof session.ip === 'string' && session.ip) {
      metaParts.push(' · IP ', h('span', { class: 'meta-strong' }, session.ip));
    }

    const item = h(
      'li',
      { class: 'list-item' },
      h('div', { class: 'item-icon' }, icon('device')),
      h(
        'div',
        { class: 'item-main' },
        h(
          'div',
          { class: 'item-title-row' },
          h('span', { class: 'item-title' }, current ? 'This device' : device),
          current ? badge('Current', 'badge-current') : null,
        ),
        h('p', { class: 'item-meta' }, metaParts),
      ),
      h(
        'div',
        { class: 'item-actions' },
        (revokeButton = button('Sign out', {
          kind: 'danger',
          size: 'sm',
          onClick: revokeSession,
        })),
      ),
      errorBox,
    );

    async function revokeSession() {
      const confirmed = await confirmDialog({
        title: current ? 'Sign out this device?' : 'Sign out this device?',
        message: current
          ? 'You’ll be signed out of this browser right away. You can sign back in with your passkey or a recovery code.'
          : `This will sign out ${device}. It will need to sign in again.`,
        confirmLabel: current ? 'Sign out here' : 'Sign out',
        danger: true,
      });
      if (!confirmed) return;

      setLiveError(errorBox, null);
      await withBusy(revokeButton, 'Signing out…', item, async () => {
        try {
          await api(`/api/sessions/${encodeURIComponent(session.id)}/revoke`, { method: 'POST' });
          if (current) {
            handleSignedOut('This browser has been signed out.', 'info');
            return;
          }
          await loadDashboard({ quiet: true, toast: 'That device was signed out.', focusId: 'sessions-heading' });
        } catch (error) {
          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t sign out that device. Please try again.'));
        }
      });
    }

    return item;
  }

  function buildPasskeysPanel() {
    const data = state.dashboard;
    let body;

    if (data.passkeysError) {
      let retryButton = null;
      retryButton = button('Try again', {
        kind: 'secondary',
        size: 'sm',
        onClick: () => refreshFrom(retryButton),
      });
      body = alertBox('warning', [h('p', null, data.passkeysError), h('div', { class: 'alert-action' }, retryButton)]);
    } else if (!data.passkeys.length) {
      body = h(
        'div',
        { class: 'empty-state' },
        h('strong', null, 'No passkeys yet.'),
        h('br'),
        'Sign out and sign in with an email code to create one.',
      );
    } else {
      body = h('ul', { class: 'list' }, data.passkeys.map(buildPasskeyItem));
    }

    const errorBox = liveError('add-passkey-error');
    let panelEl = null;
    let addButton = null;

    addButton = button('Add another passkey', {
      kind: 'secondary',
      size: 'sm',
      iconName: 'key',
      onClick: addPasskey,
    });

    async function addPasskey() {
      if (panelEl && panelEl.getAttribute('aria-busy') === 'true') return;
      setLiveError(errorBox, null);

      const supportMessage = webauthnSupportMessage();
      if (supportMessage) {
        setLiveError(errorBox, supportMessage);
        return;
      }

      await withBusy(addButton, 'Waiting for your device…', panelEl, async () => {
        let stage = 'start';
        try {
          const start = await withStepUp(() => api(API.passkeysAddStart, { method: 'POST' }));
          if (
            !start ||
            typeof start.challenge_id !== 'string' ||
            !start.challenge_id ||
            !start.options
          ) {
            setLiveError(errorBox, 'We couldn’t prepare a new passkey. Please try again.');
            return;
          }

          let publicKey;
          try {
            publicKey = prepareCreationOptions(start.options);
          } catch {
            setLiveError(errorBox, 'We couldn’t prepare a new passkey request. Please try again.');
            return;
          }

          const credential = await navigator.credentials.create({ publicKey });
          if (!credential) {
            setLiveError(errorBox, 'Your device didn’t return a passkey. Please try again.');
            return;
          }

          const serialized = serializeRegistrationCredential(credential);
          stage = 'finish';
          await withStepUp(() =>
            api(API.passkeysAddFinish, {
              method: 'POST',
              body: { challenge_id: start.challenge_id, credential: serialized },
            }),
          );

          await loadDashboard({
            quiet: true,
            toast: 'Passkey added.',
            focusId: 'passkeys-heading',
          });
        } catch (error) {
          if (error instanceof StepUpError) {
            setLiveError(errorBox, error.userMessage);
            return;
          }

          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }

          const deviceMessage = webauthnFailureMessage(error, 'add');
          if (deviceMessage) {
            setLiveError(errorBox, deviceMessage);
            return;
          }

          if (error instanceof ApiError && error.network) {
            setLiveError(
              errorBox,
              stage === 'finish'
                ? 'We couldn’t confirm that the passkey was added. Check your connection, then refresh to see if it appears.'
                : 'We couldn’t reach AuthLayer. Check your connection and try again.',
            );
            return;
          }

          if (error instanceof ApiError && (error.status === 404 || error.status === 501)) {
            setLiveError(
              errorBox,
              'This server doesn’t support adding passkeys from the dashboard yet. Ask whoever runs it to update AuthLayer.',
            );
            return;
          }

          if (error instanceof ApiError) {
            setLiveError(errorBox, humanizeError(error, 'We couldn’t add that passkey. Please try again.'));
            return;
          }

          if (error && error.message === 'incomplete_credential') {
            setLiveError(errorBox, 'Your device didn’t return a complete passkey. Please try again.');
            return;
          }

          setLiveError(
            errorBox,
            'We couldn’t add a passkey on this device. Please try again or use a different device.',
          );
        }
      });
    }

    panelEl = panel({
      id: 'passkeys-heading',
      iconName: 'key',
      title: 'Passkeys',
      subtitle: 'Devices that can sign you in without a code.',
      action: Number(state.me && state.me.passkeys) > 0 ? addButton : null,
      content: h('div', { class: 'panel-stack' }, errorBox, body),
    });
    return panelEl;
  }

  function buildSessionsPanel() {
    const data = state.dashboard;
    let body;

    if (data.sessionsError) {
      let retryButton = null;
      retryButton = button('Try again', {
        kind: 'secondary',
        size: 'sm',
        onClick: () => refreshFrom(retryButton),
      });
      body = alertBox('warning', [h('p', null, data.sessionsError), h('div', { class: 'alert-action' }, retryButton)]);
    } else if (!data.sessions.length) {
      body = h('div', { class: 'empty-state' }, 'No active sessions were found.');
    } else {
      body = h('ul', { class: 'list' }, data.sessions.map(buildSessionItem));
    }

    const errorBox = liveError('sessions-action-error');
    let panelEl = null;
    let signOutAllButton = null;

    signOutAllButton = button('Sign out everywhere', {
      kind: 'danger',
      size: 'sm',
      iconName: 'logout',
      onClick: signOutEverywhere,
    });

    async function signOutEverywhere() {
      if (panelEl && panelEl.getAttribute('aria-busy') === 'true') return;

      const confirmed = await confirmDialog({
        title: 'Sign out everywhere?',
        message:
          'This signs out every device, including this browser. You’ll need your passkey or a recovery code to sign back in.',
        confirmLabel: 'Sign out everywhere',
        danger: true,
      });
      if (!confirmed) return;

      setLiveError(errorBox, null);
      await withBusy(signOutAllButton, 'Signing out…', panelEl, async () => {
        try {
          await withStepUp(() => api(API.sessionsRevokeAll, { method: 'POST' }));
          handleSignedOut('You’ve been signed out of every device.', 'info');
        } catch (error) {
          if (error instanceof StepUpError) {
            setLiveError(errorBox, error.userMessage);
            return;
          }
          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }
          if (error instanceof ApiError && (error.status === 404 || error.status === 501)) {
            setLiveError(
              errorBox,
              'This server doesn’t support signing out everywhere yet. Ask whoever runs it to update AuthLayer.',
            );
            return;
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t sign you out everywhere. Please try again.'));
        }
      });
    }

    panelEl = panel({
      id: 'sessions-heading',
      iconName: 'device',
      title: 'Where you’re signed in',
      subtitle: 'Active sign-ins on your account. Sign out anything you don’t recognize.',
      action: signOutAllButton,
      content: h('div', { class: 'panel-stack' }, errorBox, body),
    });
    return panelEl;
  }

  function buildRecoveryPanel() {
    const remainingRaw = Number(state.me && state.me.recovery_codes_remaining);
    const remaining = Number.isFinite(remainingRaw) && remainingRaw >= 0 ? Math.trunc(remainingRaw) : 0;
    const passkeyCount = Number(state.me && state.me.passkeys);
    let regenButton = null;
    let panelEl = null;
    const errorBox = liveError('recovery-panel-error');

    regenButton = button(remaining > 0 ? 'Generate new codes' : 'Generate recovery codes', {
      kind: remaining > 0 ? 'secondary' : 'primary',
      size: 'sm',
      iconName: 'refresh',
      onClick: regenerate,
    });

    async function regenerate() {
      const confirmed = await confirmDialog({
        title: 'Generate new recovery codes?',
        message: 'Your current unused recovery codes will stop working immediately. You’ll get a new set to save.',
        confirmLabel: 'Generate codes',
      });
      if (!confirmed) return;

      setLiveError(errorBox, null);
      await withBusy(regenButton, 'Generating…', panelEl, async () => {
        try {
          const data = await withStepUp(() => api(API.recoveryRegenerate, { method: 'POST' }));
          const codes = recoverableCodes(data);
          if (!codes.length) {
            setLiveError(errorBox, 'We didn’t receive any new codes. Please try again.');
            return;
          }
          state.pendingCodes = codes;
          state.codesContext = 'regenerate';
          renderRecoveryCodes();
        } catch (error) {
          if (error instanceof StepUpError) {
            setLiveError(errorBox, error.userMessage);
            return;
          }
          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }
          setLiveError(errorBox, humanizeError(error, 'We couldn’t generate new recovery codes. Please try again.'));
        }
      });
    }

    const warning =
      remaining === 0
        ? alertBox(
            'warning',
            h(
              'p',
              null,
              passkeyCount === 1
                ? 'You have no recovery codes left and only one passkey. Generate a new set now so you don’t get locked out.'
                : 'You have no recovery codes left. Generate a new set now so you don’t get locked out.',
            ),
          )
        : null;

    const content = h(
      'div',
      null,
      h(
        'div',
        { class: 'recovery-row' },
        h(
          'div',
          { class: 'recovery-copy' },
          h(
            'p',
            { class: 'recovery-count' },
            h('strong', null, String(remaining)),
            remaining === 1 ? ' unused recovery code' : ' unused recovery codes',
          ),
          h(
            'p',
            { class: 'recovery-detail' },
            'Each code works once. Use one if you lose your device to set up a new passkey.',
          ),
        ),
        regenButton,
      ),
      warning ? h('div', { class: 'recovery-panel-alert' }, warning) : null,
      errorBox,
    );

    panelEl = panel({
      id: 'recovery-heading',
      iconName: 'shield',
      title: 'Recovery codes',
      subtitle: 'One-time backup codes for when you lose a device.',
      content,
    });
    return panelEl;
  }

  function renderDashboard({ notice = null, focusId = null } = {}) {
    if (!state.me || !state.dashboard) {
      boot();
      return;
    }

    const me = state.me;
    const dashboardData = state.dashboard;
    const email = me.user && typeof me.user.email === 'string' ? me.user.email : 'your account';
    const initial = Array.from(email.trim())[0] || '?';
    const dashboardEl = h('div', { class: 'dashboard' });

    async function refresh() {
      if (dashboardEl.getAttribute('aria-busy') === 'true') return;
      await withBusy(refreshButton, 'Refreshing…', dashboardEl, async () => {
        await loadDashboard({ quiet: true, toast: 'Dashboard updated.', focusId: 'dashboard-title' });
      });
    }

    async function logout() {
      if (dashboardEl.getAttribute('aria-busy') === 'true') return;
      await withBusy(logoutButton, 'Signing out…', dashboardEl, async () => {
        try {
          await api(API.logout, { method: 'POST' });
          handleSignedOut('You are signed out.', 'info');
        } catch (error) {
          if (isUnauthorizedError(error)) {
            handleSignedOut('Your session has ended. Please sign in again.');
            return;
          }
          state.dashAlert = humanizeError(error, 'We couldn’t sign you out. Please try again.');
          renderDashboard();
        }
      });
    }

    const refreshButton = button('Refresh', {
      kind: 'ghost',
      size: 'sm',
      iconName: 'refresh',
      onClick: refresh,
    });
    const logoutButton = button('Log out', {
      kind: 'secondary',
      size: 'sm',
      iconName: 'logout',
      onClick: logout,
    });

    const banners = [];
    const noticeNode = noticeBanner(notice);
    if (noticeNode) banners.push(noticeNode);
    if (state.dashAlert) banners.push(alertBox('error', h('p', null, state.dashAlert)));

    const stats = h(
      'div',
      { class: 'stats-grid' },
      statTile('key', countOr(me.passkeys, dashboardData.passkeys.length), 'Passkeys', 'Ways to sign in'),
      statTile('device', countOr(me.sessions, dashboardData.sessions.length), 'Active sessions', 'Signed-in devices'),
      statTile('shield', countOr(me.recovery_codes_remaining, 0), 'Recovery codes', 'One-time codes left'),
      statTile('clock', formatDate(me.session_expires_at), 'Signed in until', relativeTime(me.session_expires_at), true),
    );

    appendChildren(dashboardEl, [
      h(
        'header',
        { class: 'dash-header' },
        h(
          'div',
          { class: 'dash-identity' },
          h('div', { class: 'dash-avatar', attrs: { 'aria-hidden': 'true' } }, initial),
          h(
            'div',
            { class: 'dash-identity-text' },
            h('p', { class: 'eyebrow' }, 'Your account'),
            h('h1', { class: 'screen-title', attrs: { id: 'dashboard-title', tabindex: '-1' } }, 'Security dashboard'),
            h('p', { class: 'dash-email' }, icon('mail'), h('span', null, email)),
          ),
        ),
        h('div', { class: 'dash-actions' }, refreshButton, logoutButton),
      ),
      h('p', { class: 'dash-intro' }, 'Manage how you sign in and where your account is signed in.'),
      stats,
      banners.length ? h('div', { class: 'dash-banners' }, banners) : null,
      buildPasskeysPanel(),
      buildSessionsPanel(),
      buildRecoveryPanel(),
      h('p', { class: 'dash-footnote' }, 'AuthLayer never stores or asks for a password.'),
    ]);

    mount(dashboardEl, focusId);
  }

  /* ---------- Boot ---------- */

  function renderFatal(error) {
    const network = error instanceof ApiError && error.network;
    const message = network
      ? 'We couldn’t reach the AuthLayer server. Check your connection and try again.'
      : 'The server ran into a problem while loading your account. Please try again in a moment.';

    const retryButton = button('Try again', {
      kind: 'primary',
      block: true,
      iconName: 'refresh',
      onClick: () => boot(),
    });

    const wrap = authCard({
      eyebrow: network ? 'Connection problem' : 'Something went wrong',
      title: 'We can’t load AuthLayer',
      lead: message,
      body: h(
        'div',
        null,
        h('div', { class: 'fatal' }, h('div', { class: 'fatal-icon' }, icon('alert')), retryButton),
      ),
      footer: h('p', { class: 'tiny' }, 'If this keeps happening, contact the person who runs this server.'),
    });

    mount(wrap);
  }

  function loadingView() {
    return h(
      'div',
      { class: 'auth-wrap' },
      h(
        'section',
        {
          class: 'card auth-card',
          attrs: { 'aria-busy': 'true', 'aria-label': 'Loading AuthLayer' },
        },
        h(
          'div',
          { class: 'boot' },
          h('span', { class: 'spinner spinner-lg', attrs: { 'aria-hidden': 'true' } }),
          h('p', null, 'Checking your session…'),
        ),
      ),
    );
  }

  async function boot() {
    mount(loadingView());
    try {
      const me = await api(API.me);
      if (me && me.authenticated === true) {
        await loadDashboard({ preloadedMe: me });
      } else {
        renderSignIn();
      }
    } catch (error) {
      renderFatal(error);
    }
  }

  boot().catch(() => {
    renderFatal(new Error('boot failed'));
  });
})();
