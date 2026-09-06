import { K, kvGet, kvPut, b64, eq, u8, DEFAULT_ADMIN_PASSWORD, SESSION_TTL, LOCK_MS, COOKIE, MAX_FAILED, j, aerr } from './config.js';

export async function hashPassword(p, saltB64) {
  const salt = saltB64 ? u8(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(p), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, km, 256);
  return { hash: b64(new Uint8Array(bits)), salt: b64(salt) };
}

export async function verifyPassword(p, h, s) {
  if (!h || !s) return false;
  return eq((await hashPassword(p, s)).hash, h);
}

export async function auth(env) {
  return kvGet(env, K.auth, null);
}

export function cookie(request) {
  const c = request.headers.get("cookie") || "";
  const m = c.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? m[1] : null;
}

export function setCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`;
}

export function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

export async function newSession(env) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const token = b64(raw).replace(/[^a-zA-Z0-9]/g, "");
  const ar = await auth(env);
  const ver = Number.isInteger(ar?.sessionVersion) ? ar.sessionVersion : 0;
  await env.CONFIG_KV.put(K.session + token, JSON.stringify({ expires: Date.now() + SESSION_TTL * 1000, sessionVersion: ver }), { expirationTtl: SESSION_TTL });
  return token;
}

export async function validSession(request, env) {
  const t = cookie(request);
  if (!t) return null;
  const s = await env.CONFIG_KV.get(K.session + t, "json");
  const ar = await auth(env);
  if (!s || s.expires < Date.now()) return null;
  const ver = Number.isInteger(ar?.sessionVersion) ? ar.sessionVersion : 0;
  return s.sessionVersion === ver ? t : null;
}

export async function login(request, env) {
  let body;
  try { body = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const p = String(body?.password || "");
  const ar = await auth(env);
  const now = Date.now();
  if (ar?.lockUntil > now) return j({ ok: false, error: `Too many attempts. Try again in ${Math.ceil((ar.lockUntil - now) / 1000)}s.` }, 429);
  
  const fresh = !ar || !ar.passwordHash || !ar.salt;
  let ok = fresh ? p === DEFAULT_ADMIN_PASSWORD : await verifyPassword(p, ar.passwordHash, ar.salt);
  const must = fresh ? true : !!ar.mustChangePassword;

  if (!ok) {
    const n = (ar?.failedAttempts || 0) + 1;
    await kvPut(env, K.auth, { ... (ar || {}), passwordHash: ar?.passwordHash || null, salt: ar?.salt || null, mustChangePassword: true, failedAttempts: n, lockUntil: n >= MAX_FAILED ? now + LOCK_MS : 0, sessionVersion: Number.isInteger(ar?.sessionVersion) ? ar.sessionVersion : 0 });
    return j({ ok: false, error: "Invalid password." }, 401);
  }

  if (ar) await kvPut(env, K.auth, { ...ar, failedAttempts: 0, lockUntil: 0, sessionVersion: Number.isInteger(ar.sessionVersion) ? ar.sessionVersion : 0 });

  const token = await newSession(env);
  return j({ ok: true, mustChangePassword: must }, 200, { "Set-Cookie": setCookie(token) });
}

export async function changePassword(request, env) {
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const cur = String(b?.currentPassword || "");
  const next = String(b?.newPassword || "");
  if (next.length < 8) return j({ ok: false, error: "New password must be at least 8 characters." }, 400);
  
  const ar = await auth(env);
  const ok = !ar || !ar.passwordHash ? cur === DEFAULT_ADMIN_PASSWORD : await verifyPassword(cur, ar.passwordHash, ar.salt);
  if (!ok) return j({ ok: false, error: "Current password is incorrect." }, 401);
  
  const hs = await hashPassword(next);
  const ver = (Number.isInteger(ar?.sessionVersion) ? ar.sessionVersion : 0) + 1;
  await kvPut(env, K.auth, { passwordHash: hs.hash, salt: hs.salt, mustChangePassword: false, failedAttempts: 0, lockUntil: 0, sessionVersion: ver });
  
  const token = await newSession(env);
  return j({ ok: true }, 200, { "Set-Cookie": setCookie(token) });
}

export async function requireChanged(env) {
  const ar = await auth(env);
  return (!!ar?.passwordHash && !ar?.mustChangePassword);
}
