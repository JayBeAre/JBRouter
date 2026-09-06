import { K, kvGet, kvPut, j, aerr, cleanHeaders } from './config.js';
import { requireChanged } from './auth.js';
import { providers, pools, rolemap, routerAuth } from './providers.js';

export async function debugConfig(env) {
  return kvGet(env, K.debug, { enabled: false });
}

export async function saveDebugConfig(request, env) {
  if (!(await requireChanged(env))) return aerr("Change your password before editing configuration.", "authentication_error", 403);
  let b;
  try { b = await request.json(); } catch { return aerr("Invalid JSON body."); }
  await kvPut(env, K.debug, { enabled: !!b.enabled });
  return j({ ok: true, enabled: !!b.enabled });
}

export function sanitizeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const name = String(k).toLowerCase();
    if (name === "authorization" || name === "proxy-authorization" || name.includes("api-key") || name.includes("token") || name.includes("secret")) {
      out[k] = "[REDACTED]";
      continue;
    }
    out[k] = String(v);
  }
  return out;
}

export function providerDebugInfo(provider) {
  const keys = Array.isArray(provider?.apiKeys) ? provider.apiKeys : [];
  return {
    id: provider?.id || "",
    label: provider?.label || "",
    baseUrl: provider?.baseUrl || "",
    apiKeyCount: keys.length,
    hasApiKey: keys.length > 0,
    extraHeaderNames: Object.keys(provider?.extraHeaders || {}),
    extraHeaders: sanitizeHeaders(provider?.extraHeaders || {})
  };
}

export async function debugProviderTest(provider, model) {
  const baseUrl = String(provider?.baseUrl || "");
  if (!baseUrl) return { ok: false, error: "Provider has no baseUrl." };
  const headers = { "Content-Type": "application/json" };
  const keys = Array.isArray(provider?.apiKeys) && provider.apiKeys.length ? provider.apiKeys : [null];
  const key = keys[0];
  if (key) headers.Authorization = "Bearer " + key;
  Object.assign(headers, cleanHeaders(provider?.extraHeaders || {}));
  const payload = { model: String(model), messages: [{ role: "user", content: "Reply with exactly: JBROUTER_DEBUG_OK" }], stream: false };
  const timeoutMs = 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const response = await fetch(baseUrl, { method: "POST", headers, body: JSON.stringify(payload), signal: controller.signal });
    clearTimeout(timer);
    let text = "";
    try { text = await response.text(); } catch (err) { text = `Could not read response body: ${err?.message || "unknown error"}`; }
    const responseHeaders = {};
    for (const [k, v] of response.headers.entries()) responseHeaders[k] = /authorization|token|key|secret/i.test(k) ? "[REDACTED]" : v;
    const result = { ok: response.ok, status: response.status, statusText: response.statusText, elapsedMs: Date.now() - started, provider: providerDebugInfo(provider), model: String(model), request: { method: "POST", headers: sanitizeHeaders(headers), payloadShape: { model: payload.model, messageCount: payload.messages.length, stream: payload.stream } }, response: { headers: responseHeaders, body: text.slice(0, 4000) } };
    return result;
  } catch (err) {
    clearTimeout(timer);
    const timedOut = err?.name === "AbortError";
    return { ok: false, status: timedOut ? 504 : 502, error: timedOut ? `Upstream request timed out after ${timeoutMs} ms.` : (err?.message || "fetch failed."), elapsedMs: Date.now() - started, provider: providerDebugInfo(provider), model: String(model) };
  }
}

export async function debugRouter(request, env, url) {
  const dbg = await debugConfig(env);
  if (!dbg.enabled) return aerr("Debug mode is disabled.", "not_found", 404);
  if (url.pathname === "/debug" && request.method === "GET") {
    const [ps, pl, rm, ra] = await Promise.all([providers(env), pools(env), rolemap(env), routerAuth(env)]);
    const providerInfo = {};
    for (const id of Object.keys(ps || {})) providerInfo[id] = providerDebugInfo(ps[id]);
    const result = { ok: true, debug: { enabled: true }, routerAuth: { enabled: !!ra?.enabled }, request: { method: request.method, url: request.url, userAgent: request.headers.get("user-agent") || "", cfConnectingIp: request.headers.get("cf-connecting-ip") || null, xForwardedFor: request.headers.get("x-forwarded-for") || null, cfRay: request.headers.get("cf-ray") || null }, providers: providerInfo, pools: pl, roleMap: rm };
    return j(result);
  }
  if (url.pathname === "/debug/zen" && request.method === "GET") {
    const providerId = url.searchParams.get("provider") || "";
    const model = url.searchParams.get("model") || "";
    if (!providerId || !model) return aerr("Missing provider or model parameter.");
    const ps = await providers(env);
    const provider = ps[providerId];
    if (!provider) return aerr(`Provider "${providerId}" is not configured.`, "invalid_request_error", 404);
    return j(await debugProviderTest(provider, model));
  }
  return aerr("Debug endpoint not found.", "not_found", 404);
}
