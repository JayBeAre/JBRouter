import { j, aerr, cleanHeaders, packToolCallId, unpackToolCallId } from './config.js';
import { providers, pools, rolemap, routerAuth } from './providers.js';

/*
 * Per-provider-call timeout. This has to be generous: Gemini's
 * reasoning models can legitimately take 30-50+ seconds to
 * produce a full non-streamed response for a non-trivial prompt
 * (we always request stream:false upstream and buffer the whole
 * reply before converting it, so the client sees nothing until
 * this finishes). Too short a timeout kills real, working
 * requests — which is what a 20s value was doing. This is meant
 * to catch a genuinely hung connection, not a slow-but-alive one.
 */
const PROVIDER_TIMEOUT_MS = 55000;

/*
 * Hard ceiling on how long the ENTIRE router (across every pool
 * in the fallback chain) is allowed to keep trying before giving
 * up. Must be comfortably larger than PROVIDER_TIMEOUT_MS so a
 * single slow-but-legitimate call isn't cut off mid-flight; this
 * mainly bounds the case where MULTIPLE entries in the chain are
 * each slow/failing in sequence.
 */
const ROUTER_BUDGET_MS = 90000;

function blockText(p) {
  if (!p) return "";
  if (p.type === "text") return p.text || "";
  if (p.type === "image") return "[image content]";
  return JSON.stringify(p);
}

function toOpenAIMessages(ms) {
  const out = [];
  for (const m of ms || []) {
    if (typeof m.content === "string") {
      out.push({ role: m.role, content: m.content });
      continue;
    }
    if (!Array.isArray(m.content)) {
      out.push({ role: m.role, content: String(m.content ?? "") });
      continue;
    }
    if (m.role === "user") {
      const t = []; const tr = [];
      for (const p of m.content || []) {
        if (!p) continue;
        if (p.type === "text") t.push(p.text || "");
        else if (p.type === "tool_result") {
          /*
           * p.tool_use_id may be a "packed" id containing
           * round-tripped vendor metadata (see
           * packToolCallId/unpackToolCallId in config.ts). Only
           * the REAL id should go upstream — the provider has no
           * idea about our packing scheme.
           */
          const { id: realToolCallId } = unpackToolCallId(p.tool_use_id);
          tr.push({ role: "tool", tool_call_id: realToolCallId || p.tool_use_id, content: typeof p.content === "string" ? p.content : JSON.stringify(p.content ?? "") });
        }
        else t.push(blockText(p));
      }
      if (t.length) out.push({ role: "user", content: t.join("\n") });
      out.push(...tr);
      continue;
    }
    if (m.role === "assistant") {
      const t = []; const tc = [];
      for (const p of m.content || []) {
        if (!p) continue;
        if (p.type === "text") t.push(p.text || "");
        else if (p.type === "tool_use") {
          /*
           * Unpack any vendor metadata (e.g. Gemini's
           * thought_signature) stashed in the id when this tool
           * call was first returned to Claude, and re-attach it
           * so the provider recognizes its own history.
           */
          const { id: realId, extraContent } = unpackToolCallId(p.id || "");
          const call = { id: realId || `tool_${crypto.randomUUID()}`, type: "function", function: { name: p.name || "", arguments: JSON.stringify(p.input ?? {}) } };
          if (extraContent) call.extra_content = extraContent;
          tc.push(call);
        }
        else t.push(blockText(p));
      }
      const x = { role: "assistant", content: t.length ? t.join("\n") : null };
      if (tc.length) x.tool_calls = tc;
      out.push(x);
      continue;
    }
    out.push({ role: m.role, content: JSON.stringify(m.content) });
  }
  return out;
}

function toOpenAITools(ts) {
  if (!Array.isArray(ts)) return undefined;
  return ts.filter((t) => t && t.name).map((t) => ({ type: "function", function: { name: t.name, description: t.description || "", parameters: t.input_schema || { type: "object", properties: {} } } }));
}

function toolChoice(x) {
  if (!x) return undefined;
  if (x.type === "auto") return "auto";
  if (x.type === "any") return "required";
  if (x.type === "tool" && x.name) return { type: "function", function: { name: x.name } };
  return undefined;
}

function textFromOpenAI(m) {
  if (!m) return "";
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) return m.content.map((x) => typeof x === "string" ? x : x?.type === "text" ? x.text || "" : "").join("");
  return "";
}

function fromOpenAI(r, requested, backend) {
  const c = r?.choices?.[0];
  if (!c) throw Error("Provider returned no choices.");
  const m = c.message || {};
  const hasText = typeof m.content === "string" ? m.content.length > 0 : Array.isArray(m.content) && m.content.some((x) => typeof x === "string" ? x.length > 0 : x?.type === "text" && typeof x.text === "string" && x.text.length > 0);
  const hasTools = Array.isArray(m.tool_calls) && m.tool_calls.length > 0;
  if (!hasText && !hasTools) throw Error("Provider returned an empty assistant response.");
  const content = [];
  const t = textFromOpenAI(m);
  if (t) content.push({ type: "text", text: t });
  for (const tc of m.tool_calls || []) {
    let input = {};
    try { input = JSON.parse(tc?.function?.arguments || "{}"); } catch {}
    /*
     * Round-trip any vendor-specific tool-call metadata (e.g.
     * Gemini's extra_content.google.thought_signature) by packing
     * it into the id we hand back to Claude.
     */
    const rawId = tc.id || `tool_${crypto.randomUUID()}`;
    const packedId = packToolCallId(rawId, tc.extra_content || null);
    content.push({ type: "tool_use", id: packedId, name: tc?.function?.name || "", input });
  }
  return { id: r.id || `msg_${crypto.randomUUID()}`, type: "message", role: "assistant", model: requested, content, stop_reason: c.finish_reason === "tool_calls" ? "tool_use" : c.finish_reason === "length" ? "max_tokens" : "end_turn", stop_sequence: null, usage: { input_tokens: r?.usage?.prompt_tokens || 0, output_tokens: r?.usage?.completion_tokens || 0 }, _backend_model: backend };
}

function shouldFallback(status, text) {
  const x = String(text || "").toLowerCase();
  return (status === 429 || status >= 500 || status === 401 || status === 403 || status === 404 || x.includes("freeusagelimiterror") || x.includes("model unavailable") || x.includes("not found for api") || x.includes("api key not valid") || x.includes("permission_denied") || x.includes("invalid authentication credentials") || x.includes("rate limit exceeded") || x.includes("temporarily unavailable"));
}

async function callProvider(provider, model, key, body, ms, tools) {
  const baseUrl = String(provider.baseUrl || "");
  const h = { "Content-Type": "application/json" };
  if (key) h.Authorization = "Bearer " + key;
  Object.assign(h, cleanHeaders(provider.extraHeaders));
  const payload = { model, messages: toOpenAIMessages(ms), stream: false };
  if (body.max_tokens !== undefined) payload.max_tokens = body.max_tokens;
  if (body.temperature !== undefined) payload.temperature = body.temperature;
  if (body.top_p !== undefined) payload.top_p = body.top_p;
  if (Array.isArray(tools) && tools.length) {
    payload.tools = tools;
    const tc = toolChoice(body.tool_choice);
    if (tc !== undefined) payload.tool_choice = tc;
  }
  return fetch(baseUrl, { method: "POST", headers: h, body: JSON.stringify(payload), signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS) });
}

async function callWithKeys(provider, model, body, ms, tools) {
  const keys = Array.isArray(provider.apiKeys) && provider.apiKeys.length ? provider.apiKeys : [null];
  const attempts = [];
  let last = null;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    try {
      const r = await callProvider(provider, model, key, body, ms, tools);
      const text = await r.text();
      const retryAfter = r.headers.get("retry-after") || null;
      last = { ok: r.ok, status: r.status, text, contentType: r.headers.get("content-type"), keyIndex: i, retryAfter };
      attempts.push({ keyIndex: i, status: r.status, ok: r.ok });
      if (r.ok) return { ...last, attempts };
      if (shouldFallback(r.status, text)) continue;
      return { ...last, attempts };
    } catch (err) {
      last = { ok: false, status: 502, text: err?.message || "Provider request failed.", contentType: "application/json", keyIndex: i, retryAfter: null };
      attempts.push({ keyIndex: i, status: 502, ok: false, error: err?.message || "Provider request failed." });
      continue;
    }
  }
  return { ...(last || { ok: false, status: 502, text: "All provider keys failed.", contentType: "application/json", retryAfter: null }), attempts };
}

function sse(msg) {
  const ev = [];
  ev.push(["message_start", { type: "message_start", message: { id: msg.id, type: "message", role: "assistant", model: msg.model, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: msg.usage.input_tokens, output_tokens: 0 } } }]);
  msg.content.forEach((b, i) => {
    if (b.type === "text") {
      ev.push(["content_block_start", { type: "content_block_start", index: i, content_block: { type: "text", text: "" } }]);
      ev.push(["content_block_delta", { type: "content_block_delta", index: i, delta: { type: "text_delta", text: b.text || "" } }]);
      ev.push(["content_block_stop", { type: "content_block_stop", index: i }]);
    } else if (b.type === "tool_use") {
      ev.push(["content_block_start", { type: "content_block_start", index: i, content_block: { type: "tool_use", id: b.id, name: b.name, input: {} } }]);
      ev.push(["content_block_delta", { type: "content_block_delta", index: i, delta: { type: "input_json_delta", partial_json: JSON.stringify(b.input || {}) } }]);
      ev.push(["content_block_stop", { type: "content_block_stop", index: i }]);
    }
  });
  ev.push(["message_delta", { type: "message_delta", delta: { stop_reason: msg.stop_reason, stop_sequence: null }, usage: { output_tokens: msg.usage.output_tokens } }]);
  ev.push(["message_stop", { type: "message_stop" }]);
  return ev.map((e) => `event: ${e[0]}\ndata: ${JSON.stringify(e[1])}\n\n`).join("");
}

function resolvePoolId(requested, rm, poolsConfig) {
  const name = String(requested || "").toLowerCase();
  const rules = Array.isArray(rm?.rules) ? rm.rules : [];
  const matches = rules.filter((r) => r && r.keyword && r.poolId && name.includes(String(r.keyword).toLowerCase())).sort((a, b) => String(b.keyword).length - String(a.keyword).length);
  for (const r of matches) if (poolsConfig?.[r.poolId]) return r.poolId;
  if (rm?.defaultPoolId && poolsConfig?.[rm.defaultPoolId]) return rm.defaultPoolId;
  return Object.keys(poolsConfig || {})[0] || "";
}

export async function router(request, env) {
  const ra = await routerAuth(env);
  if (ra.enabled) {
    const authHeader = request.headers.get("authorization") || "";
    if (!/^Bearer\s+\S+$/i.test(authHeader) || authHeader.slice(7).trim() !== ra.token) return aerr("Unauthorized.", "authentication_error", 401);
  }
  let body;
  try { body = await request.json(); } catch { return aerr("Invalid JSON request body."); }

  /*
   * Reject malformed requests up front instead of forwarding an
   * empty/garbage payload to every provider in the fallback
   * chain — that wastes attempts and can trip a provider's own
   * WAF (some return a blanket "Access denied by security
   * policy" for empty-messages requests).
   */
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return aerr('"messages" must be a non-empty array.', "invalid_request_error", 400);
  }

  const requested = String(body.model || "default");
  const [ps, pls, rm] = await Promise.all([providers(env), pools(env), rolemap(env)]);
  const startPoolId = resolvePoolId(requested, rm, pls);
  if (!startPoolId) return aerr(`No pool configured for model "${requested}".`);
  const ms = body.messages || [];
  const tools = toOpenAITools(body.tools);
  let lastStatus = 503; let lastRetryAfter = null; const attempts = []; const visitedPools = new Set();
  let currentPoolId = startPoolId;
  const routerStartedAt = Date.now();
  let budgetExceeded = false;
  while (currentPoolId && !visitedPools.has(currentPoolId)) {
    visitedPools.add(currentPoolId);
    const pool = pls[currentPoolId];
    if (!pool || !Array.isArray(pool.entries) || !pool.entries.length) { currentPoolId = pool?.fallbackPoolId || null; continue; }
    for (let index = 0; index < pool.entries.length; index++) {
      if (Date.now() - routerStartedAt > ROUTER_BUDGET_MS) {
        attempts.push({ pool: currentPoolId, index, providerId: "-", model: "-", status: 504, error: "Router time budget exceeded." });
        lastStatus = 504;
        budgetExceeded = true;
        break;
      }
      const e = pool.entries[index];
      const providerId = String(e?.providerId || ""); const backendModel = String(e?.model || "");
      if (!providerId || !backendModel) { attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: 400, error: "Invalid pool entry." }); lastStatus = 400; continue; }
      const p = ps[providerId];
      if (!p) { attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: 502, error: `Provider "${providerId}" is not configured.` }); lastStatus = 502; continue; }
      let r;
      try { r = await callWithKeys(p, backendModel, body, ms, tools); } catch (err) { const msg = err?.message || "Provider request failed."; attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: 502, error: msg }); lastStatus = 502; continue; }
      if (r?.retryAfter) lastRetryAfter = r.retryAfter;
      attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: r?.status || 502, ok: !!r?.ok, error: !r?.ok ? String(r?.text || "").slice(0, 500) : undefined });
      if (!r?.ok) { lastStatus = r?.status || 502; if (shouldFallback(r?.status, r?.text)) continue; return new Response(r.text, { status: r.status || 502, headers: { "content-type": r.contentType || "application/json", "X-Backend-Provider": providerId, "X-Backend-Model": backendModel, "X-Backend-Pool": currentPoolId } }); }
      let parsed;
      try { parsed = JSON.parse(r.text); } catch { lastStatus = 502; attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: 502, error: `${providerId}/${backendModel} returned invalid JSON.` }); continue; }
      let msg;
      try { msg = fromOpenAI(parsed, requested, backendModel); } catch (err) { lastStatus = 502; attempts.push({ pool: currentPoolId, index, providerId, model: backendModel, status: 502, error: `${providerId}/${backendModel}: ${err?.message || "Invalid provider response."}` }); continue; }
      const headers = { "X-Backend-Provider": providerId, "X-Backend-Model": backendModel, "X-Backend-Pool": currentPoolId, "X-Router-Attempt": String(attempts.length), "X-Router-Attempts": String(attempts.length) };
      if (body.stream === true) return new Response(sse(msg), { status: 200, headers: { "content-type": "text/event-stream", "cache-control": "no-cache", ...headers } });
      return j(msg, 200, headers);
    }
    if (budgetExceeded) break;
    currentPoolId = pool.fallbackPoolId || null;
  }
  const summary = attempts.map((a) => { const poolTag = a.pool ? `[${a.pool}] ` : ""; const provider = a.providerId || "?"; const model = a.model || "?"; const status = a.status || "?"; const error = a.error ? String(a.error).slice(0, 300) : ""; return `${poolTag}${provider}/${model} → ${status}` + (error ? ` → ${error}` : ""); }).join(" | ");
  const finalHeaders = {};
  if (lastStatus === 429) finalHeaders["Retry-After"] = lastRetryAfter || "30";
  return aerr(`All models failed (starting pool "${startPoolId}"). Attempts: ${summary}`, "upstream_error", lastStatus, finalHeaders);
}
