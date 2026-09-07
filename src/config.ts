export const DEFAULT_ADMIN_PASSWORD = "changeme123";
export const SESSION_TTL = 60 * 60 * 12;
export const MAX_FAILED = 5;
export const LOCK_MS = 5 * 60 * 1000;
export const COOKIE = "admin_session";

export const K = {
  auth: "config:auth",
  providers: "config:providers",
  pools: "config:pools",
  rolemap: "config:rolemap",
  routerAuth: "config:routerAuth",
  debug: "config:debug",
  session: "session:"
};

export const DEFAULT_PROVIDERS = {
  "opencode-zen": {
    id: "opencode-zen",
    label: "OpenCode Zen (free)",
    baseUrl: "https://opencode.ai/zen/v1/chat/completions",
    extraHeaders: {},
    apiKeys: []
  }
};

export const DEFAULT_POOLS = {
  "pool-opus": {
    id: "pool-opus",
    label: "Opus Pool",
    entries: [{}],
    fallbackPoolId: ""
  },
  "pool-sonnet": {
    id: "pool-sonnet",
    label: "Sonnet Pool",
    entries: [
      { providerId: "opencode-zen", model: "laguna-s-2.1-free" },
      { providerId: "opencode-zen", model: "hy3-free" },
      { providerId: "opencode-zen", model: "nemotron-3-ultra-free" }
    ],
    fallbackPoolId: ""
  },
  "pool-haiku": {
    id: "pool-haiku",
    label: "Haiku Pool",
    entries: [
      { providerId: "opencode-zen", model: "hy3-free" },
      { providerId: "opencode-zen", model: "nemotron-3.5-lightning-free" },
      { providerId: "opencode-zen", model: "laguna-s-2.1-free" },
      { providerId: "opencode-zen", model: "x-preview-f-free" },
      { providerId: "opencode-zen", model: "nemotron-3-ultra-free" }
    ],
    fallbackPoolId: "pool-sonnet"
  }
};

export const DEFAULT_ROLEMAP = {
  rules: [
    { keyword: "opus", poolId: "pool-opus" },
    { keyword: "haiku", poolId: "pool-haiku" },
    { keyword: "sonnet", poolId: "pool-sonnet" }
  ],
  defaultPoolId: "pool-opus"
};

export const j = (x, s = 200, h = {}) =>
  new Response(JSON.stringify(x), {
    status: s,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...h
    }
  });

export const aerr = (m, t = "invalid_request_error", s = 400, h = {}) =>
  j({ type: "error", error: { type: t, message: m } }, s, h);

export const b64 = (b) => {
  let x = "";
  for (const v of b) x += String.fromCharCode(v);
  return btoa(x);
};

export const u8 = (s) => {
  const x = atob(s);
  const b = new Uint8Array(x.length);
  for (let i = 0; i < x.length; i++) b[i] = x.charCodeAt(i);
  return b;
};

export const eq = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
};

export const mask = (k) => (!k || k.length < 4 ? "••••" : `••••${k.slice(-4)}`);

/*
 * ============================================================
 * TOOL-CALL METADATA ROUND-TRIPPING
 * ============================================================
 *
 * Some OpenAI-compatible providers (Gemini 3.x is the known case
 * as of 2026) attach extra, non-standard metadata to each tool
 * call they return — e.g.:
 *
 *   tool_calls[i].extra_content.google.thought_signature
 *
 * ...and then REQUIRE that exact value to be echoed back on the
 * corresponding tool call when the conversation history is
 * replayed on a later turn. If it's missing, the provider
 * rejects the request ("Function call is missing a
 * thought_signature" 400).
 *
 * Claude has no field for this, but it DOES treat tool_use.id as
 * an opaque string and echoes it back byte-for-byte in the
 * matching tool_result.tool_use_id. So we smuggle the metadata
 * inside the id we hand back to Claude, and unpack it again
 * whenever we rebuild an OpenAI-style request from history.
 *
 * This is intentionally generic, not Gemini-specific — any
 * OpenAI-compatible provider that sends extra_content on a tool
 * call gets this same round-tripping for free.
 * ============================================================
 */

export const TC_ID_SEP = "::x::";

export function packToolCallId(id, extraContent) {
  if (!extraContent) return id;
  try {
    return id + TC_ID_SEP + btoa(JSON.stringify(extraContent));
  } catch {
    return id;
  }
}

export function unpackToolCallId(packed) {
  const raw = String(packed || "");
  const idx = raw.indexOf(TC_ID_SEP);
  if (idx === -1) return { id: raw, extraContent: null };
  const id = raw.slice(0, idx);
  const encoded = raw.slice(idx + TC_ID_SEP.length);
  let extraContent = null;
  try {
    extraContent = JSON.parse(atob(encoded));
  } catch {
    extraContent = null;
  }
  return { id, extraContent };
}

export async function kvGet(env, key, def) {
  const v = await env.CONFIG_KV.get(key, "json");
  return v ?? def;
}

export const kvPut = (env, key, v) => env.CONFIG_KV.put(key, JSON.stringify(v));

export function cleanHeaders(h) {
  if (!h || typeof h !== "object" || Array.isArray(h)) return {};
  const o = {};
  for (const [k, v] of Object.entries(h)) o[String(k)] = String(v);
  return o;
}
