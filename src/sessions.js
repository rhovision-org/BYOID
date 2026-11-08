import { randomBase64Url, safeEqual } from './crypto.js';

export const SESSION_COOKIE = 'byoid_sid';

export function parseCookies(header = '') {
  const cookies = {};
  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = value;
    }
  }
  return cookies;
}

export function serializeCookie(name, value, { maxAge, secure = false, sameSite = 'Lax', path = '/' } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`, 'HttpOnly'];
  if (typeof maxAge === 'number') parts.push(`Max-Age=${Math.floor(maxAge)}`);
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

export class SessionStore {
  constructor({ ttlMs = 60 * 60 * 1000 } = {}) {
    this.ttlMs = ttlMs;
    this.sessions = new Map();
    this.timer = setInterval(() => this.sweep(), 5 * 60 * 1000);
    this.timer.unref?.();
  }

  create(initial = {}) {
    const now = Date.now();
    const id = randomBase64Url(32);
    const session = { id, createdAt: now, updatedAt: now, ...initial };
    this.sessions.set(id, session);
    return session;
  }

  get(id) {
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session) return null;
    if (Date.now() - session.updatedAt > this.ttlMs) {
      this.sessions.delete(id);
      return null;
    }
    return session;
  }

  update(id, patch) {
    const session = this.get(id);
    if (!session) return null;
    Object.assign(session, patch, { updatedAt: Date.now() });
    return session;
  }

  destroy(id) {
    if (id) this.sessions.delete(id);
  }

  sweep() {
    const cutoff = Date.now() - this.ttlMs;
    for (const [id, session] of this.sessions) {
      if (session.updatedAt < cutoff) this.sessions.delete(id);
    }
  }
}

export function readSession(req, store) {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[SESSION_COOKIE];
  return { sid, session: sid ? store.get(sid) : null };
}

export function ensureSession(req, res, store, { secure = false } = {}) {
  const { sid, session } = readSession(req, store);
  if (session) return { sid, session, created: false };
  const created = store.create();
  res.setHeader(
    'set-cookie',
    serializeCookie(SESSION_COOKIE, created.id, { maxAge: store.ttlMs / 1000, secure }),
  );
  return { sid: created.id, session: created, created: true };
}

export function sameState(expected, received) {
  return Boolean(expected && received && safeEqual(expected, received));
}
