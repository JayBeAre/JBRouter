import { K, kvGet, kvPut, j, aerr, cleanHeaders, DEFAULT_PROVIDERS, DEFAULT_POOLS, DEFAULT_ROLEMAP, mask } from './config.js';
import { requireChanged } from './auth.js';

export function redacted(ps) {
  const o = {};
  for (const id of Object.keys(ps)) {
    const p = ps[id];
    o[id] = { id: p.id, label: p.label, baseUrl: p.baseUrl, extraHeaders: p.extraHeaders || {}, apiKeyCount: Array.isArray(p.apiKeys) ? p.apiKeys.length : 0, apiKeysMasked: (p.apiKeys || []).map(mask) };
  }
  return o;
}

export async function providers(env) {
  const stored = await kvGet(env, K.providers, DEFAULT_PROVIDERS);
  const ps = {};
  let changed = false;

  for (const id of Object.keys(stored || {})) {
    const p = stored[id] || {};
    if (p.kind === "gemini" || p.kind === "anthropic") {
      changed = true;
      continue;
    }
    const normalized = {
      id: p.id || id,
      label: p.label || id,
      baseUrl: String(p.baseUrl || ""),
      extraHeaders: cleanHeaders(p.extraHeaders || {}),
      apiKeys: Array.isArray(p.apiKeys) ? p.apiKeys : []
    };
    if (p.kind !== undefined || p.anthropicVersion !== undefined) changed = true;
    ps[id] = normalized;
  }
  if (changed) await kvPut(env, K.providers, ps);
  return ps;
}

export async function pools(env) {
  return kvGet(env, K.pools, DEFAULT_POOLS);
}

export async function rolemap(env) {
  return kvGet(env, K.rolemap, DEFAULT_ROLEMAP);
}

export async function routerAuth(env) {
  return kvGet(env, K.routerAuth, { enabled: false, token: "" });
}

export async function saveProvider(request, env) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const ps = await providers(env);
  const id = String(b.id || "").trim() || `provider-${crypto.randomUUID().slice(0, 8)}`;
  const old = ps[id] || {};
  let keys = Array.isArray(old.apiKeys) ? old.apiKeys : [];
  if (typeof b.apiKeysRaw === "string" && b.apiKeysRaw.trim()) {
    keys = b.apiKeysRaw.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  } else if (b.clearApiKeys === true) {
    keys = [];
  }
  ps[id] = { id, label: String(b.label || id), baseUrl: String(b.baseUrl || ""), extraHeaders: cleanHeaders(b.extraHeaders !== undefined ? b.extraHeaders : old.extraHeaders || {}), apiKeys: keys };
  await kvPut(env, K.providers, ps);
  return j({ ok: true, id });
}

export async function deleteProvider(env, id) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  const ps = await providers(env);
  delete ps[id];
  await kvPut(env, K.providers, ps);
  return j({ ok: true });
}

export async function savePool(request, env) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const pl = await pools(env);
  const id = String(b.id || "").trim() || `pool-${crypto.randomUUID().slice(0, 8)}`;
  const entries = Array.isArray(b.entries) ? b.entries.filter((e) => e && e.providerId && e.model).map((e) => ({ providerId: String(e.providerId), model: String(e.model) })) : [];
  pl[id] = { id, label: String(b.label || id), entries, fallbackPoolId: String(b.fallbackPoolId || "") };
  await kvPut(env, K.pools, pl);
  return j({ ok: true, id });
}

export async function deletePool(env, id) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  const pl = await pools(env);
  delete pl[id];
  for (const otherId of Object.keys(pl)) if (pl[otherId].fallbackPoolId === id) pl[otherId] = { ...pl[otherId], fallbackPoolId: "" };
  await kvPut(env, K.pools, pl);
  const rm = await rolemap(env);
  rm.rules = (rm.rules || []).filter((r) => r.poolId !== id);
  if (rm.defaultPoolId === id) rm.defaultPoolId = Object.keys(pl)[0] || "";
  await kvPut(env, K.rolemap, rm);
  return j({ ok: true });
}

export async function saveRoleMap(request, env) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const rm = {
    rules: Array.isArray(b.rules) ? b.rules.filter((r) => r && r.keyword && r.poolId).map((r) => ({ keyword: String(r.keyword).toLowerCase(), poolId: String(r.poolId) })) : [],
    defaultPoolId: String(b.defaultPoolId || "")
  };
  await kvPut(env, K.rolemap, rm);
  return j({ ok: true });
}

export async function saveRouterAuth(request, env) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  const enabled = !!b.enabled;
  const token = String(b.token || "").trim();
  if (enabled && token.length < 32) return j({ ok: false, error: "Router bearer token must be at least 32 characters." }, 400);
  await kvPut(env, K.routerAuth, { enabled, token });
  return j({ ok: true, enabled, token });
}
