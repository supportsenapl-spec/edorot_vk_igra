/*
 * Cloudflare Worker backend for ЕДОРОТ — VK Mini App.
 *
 * Required Worker settings:
 *   Secret: VK_APP_SECRET   = protected key of the VK Mini App
 *   Secret: SESSION_SECRET  = long random secret, used for sessions
 *   Variable: VK_APP_ID     = numeric VK Mini App ID
 *   KV binding: LEADERBOARD = KV namespace for leaderboard data
 *
 * The client never chooses the UID used by the leaderboard.
 * UID is taken only from a successfully verified VK launch query.
 */

const ALLOWED_ORIGIN = 'https://supportsenapl-spec.github.io';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SCORE = 100_000_000;
const MAX_NAME_LENGTH = 32;

const CORS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Vary': 'Origin',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS,
    },
  });
}

function base64Url(bytes) {
  let binary = '';
  const data = new Uint8Array(bytes);
  for (let i = 0; i < data.length; i += 0x8000) {
    binary += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value) {
  let s = String(value).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(message),
  ));
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/*
 * VK launch-parameter verification.
 * VK signs only parameters whose names start with vk_, sorted by name,
 * using HMAC-SHA256 and the protected app key. The resulting digest is
 * base64url encoded without padding and compared with `sign`.
 */
async function verifyVKLaunchQuery(query, env) {
  const params = new URLSearchParams(String(query || '').replace(/^\?/, ''));
  const sign = params.get('sign');
  if (!sign) throw new Error('missing VK sign');

  const signed = [];
  for (const [key, value] of params.entries()) {
    if (key.startsWith('vk_')) signed.push([key, value]);
  }
  if (!signed.length) throw new Error('missing VK launch parameters');

  signed.sort((a, b) => a[0].localeCompare(b[0]));
  const checkString = signed
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');

  const expected = base64Url(await hmac(env.VK_APP_SECRET, checkString));
  const expectedBytes = new TextEncoder().encode(expected);
  const receivedBytes = new TextEncoder().encode(sign);
  if (!constantTimeEqual(expectedBytes, receivedBytes)) {
    throw new Error('invalid VK sign');
  }

  const uid = params.get('vk_user_id');
  const appId = params.get('vk_app_id');
  if (!uid || !/^\d+$/.test(uid)) throw new Error('invalid VK user id');
  if (!appId || !/^\d+$/.test(appId)) throw new Error('invalid VK app id');
  if (String(appId) !== String(env.VK_APP_ID)) throw new Error('wrong VK app id');

  // If VK provides a timestamp, reject very old/future launch data.
  const ts = params.get('vk_ts');
  if (ts && /^\d+$/.test(ts)) {
    const age = Date.now() - Number(ts) * 1000;
    if (age < -5 * 60 * 1000 || age > SESSION_TTL_MS) {
      throw new Error('expired VK launch parameters');
    }
  }

  return { uid, appId };
}

async function createSession(uid, env) {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = `${uid}.${expiresAt}`;
  const signature = base64Url(await hmac(env.SESSION_SECRET, payload));
  return `${base64Url(new TextEncoder().encode(payload))}.${signature}`;
}

async function verifySession(token, env) {
  if (!token) throw new Error('missing session');
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('invalid session');

  const payload = new TextDecoder().decode(fromBase64Url(parts[0]));
  const expected = await hmac(env.SESSION_SECRET, payload);
  const received = fromBase64Url(parts[1]);
  if (!constantTimeEqual(expected, received)) throw new Error('invalid session signature');

  const dot = payload.lastIndexOf('.');
  if (dot <= 0) throw new Error('invalid session payload');
  const uid = payload.slice(0, dot);
  const expiresAt = Number(payload.slice(dot + 1));
  if (!/^\d+$/.test(uid) || !Number.isFinite(expiresAt) || expiresAt < Date.now()) {
    throw new Error('expired session');
  }
  return uid;
}

function cleanName(value) {
  return String(value ?? 'Игрок')
    .replace(/[\u0000-\u001F\u007F<>]/g, '')
    .trim()
    .slice(0, MAX_NAME_LENGTH) || 'Игрок';
}

function cleanScore(value) {
  const score = Number(value);
  return Number.isInteger(score) && score >= 0 && score <= MAX_SCORE ? score : null;
}

function utcDate() {
  return new Date().toISOString().slice(0, 10);
}

function validDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || ''));
}

async function saveBest(env, key, entry) {
  const current = await env.LEADERBOARD.get(key, 'json');
  if (!current || Number(entry.score) > Number(current.score)) {
    await env.LEADERBOARD.put(key, JSON.stringify(entry));
    return entry;
  }
  // Keep the best score, but allow a corrected display name.
  if (current.name !== entry.name) {
    const updated = { ...current, name: entry.name };
    await env.LEADERBOARD.put(key, JSON.stringify(updated));
    return updated;
  }
  return current;
}

async function getLeaderboard(env, prefix, limit) {
  const listed = await env.LEADERBOARD.list({ prefix, limit: 1000 });
  const entries = [];
  for (const key of listed.keys) {
    const value = await env.LEADERBOARD.get(key.name, 'json');
    if (value && cleanScore(value.score) !== null) {
      entries.push({
        uid: String(value.uid || key.name.slice(prefix.length)),
        name: cleanName(value.name),
        score: Number(value.score),
      });
    }
  }
  entries.sort((a, b) => b.score - a.score);
  return entries.slice(0, limit);
}

function requireEnv(env) {
  if (!env.VK_APP_SECRET || !env.VK_APP_ID || !env.SESSION_SECRET || !env.LEADERBOARD) {
    throw new Error('Worker is not configured: VK_APP_ID, VK_APP_SECRET, SESSION_SECRET and LEADERBOARD are required');
  }
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (request.headers.get('Origin') && request.headers.get('Origin') !== ALLOWED_ORIGIN) {
      return json({ error: 'origin not allowed' }, 403);
    }

    try {
      requireEnv(env);
      const url = new URL(request.url);

      if (url.pathname === '/auth' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const identity = await verifyVKLaunchQuery(body.query, env);
        const token = await createSession(identity.uid, env);
        return json({ ok: true, token, uid: identity.uid });
      }

      const authorization = request.headers.get('Authorization') || '';
      const token = authorization.replace(/^Bearer\s+/i, '');
      const uid = await verifySession(token, env);

      if (url.pathname === '/score' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const score = cleanScore(body.score);
        if (score === null) return json({ error: 'invalid score' }, 400);
        const entry = { uid, name: cleanName(body.name), score };
        const saved = await saveBest(env, `lb:${uid}`, entry);
        return json({ ok: true, entry: saved });
      }

      if (url.pathname === '/leaderboard' && request.method === 'GET') {
        const limit = Math.min(Math.max(Number(url.searchParams.get('limit') || 20), 1), 100);
        return json({ entries: await getLeaderboard(env, 'lb:', limit) });
      }

      if (url.pathname === '/daily-score' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const score = cleanScore(body.score);
        if (score === null) return json({ error: 'invalid score' }, 400);
        // The server chooses the date; the client cannot submit a result for another day.
        const date = utcDate();
        const entry = { uid, name: cleanName(body.name), score, date };
        const saved = await saveBest(env, `dlb:${date}:${uid}`, entry);
        return json({ ok: true, entry: saved });
      }

      if (url.pathname === '/daily-leaderboard' && request.method === 'GET') {
        const requestedDate = url.searchParams.get('date');
        const date = validDate(requestedDate) ? requestedDate : utcDate();
        const limit = Math.min(Math.max(Number(url.searchParams.get('limit') || 20), 1), 100);
        return json({ entries: await getLeaderboard(env, `dlb:${date}:`, limit) });
      }

      if (url.pathname === '/daily-me' && request.method === 'GET') {
        const date = utcDate();
        const entry = await env.LEADERBOARD.get(`dlb:${date}:${uid}`, 'json');
        return json({ score: entry && cleanScore(entry.score) !== null ? Number(entry.score) : 0 });
      }

      return json({ error: 'not found' }, 404);
    } catch (error) {
      const message = String(error?.message || error);
      const status = /missing session|invalid session|expired session|VK sign|VK launch|wrong VK app|origin/i.test(message) ? 401 : 500;
      return json({ error: status === 500 ? 'server error' : message }, status);
    }
  },
};
