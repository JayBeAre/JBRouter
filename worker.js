/*
  JBRouter — Cloudflare Worker

  - Claude/Anthropic-compatible /v1/messages endpoint
  - Dynamic providers, pools and model-role mapping in KV
  - Password-protected /admin panel
  - First login uses DEFAULT_ADMIN_PASSWORD and forces a change
  - PBKDF2 password hashing + session version invalidation
  - Optional bearer auth for /v1/messages, configurable in /admin
  - Provider kinds: openai, gemini, anthropic
  - Per-provider API-key rotation
  - Custom provider headers
  - NEW: cross-pool fallback chaining (pool.fallbackPoolId) — when
    every entry in a pool fails (e.g. a shared free-tier quota is
    exhausted across ALL models in that pool, which key/model
    rotation alone can't fix), the router moves on to another
    whole pool instead of giving up.
  - NEW: Retry-After passthrough on total failure, so clients back
    off sensibly instead of hammering an exhausted pool.
*/

const DEFAULT_ADMIN_PASSWORD = "changeme123"; // CHANGE BEFORE DEPLOYING
const SESSION_TTL = 60 * 60 * 12;
const MAX_FAILED = 5;
const LOCK_MS = 5 * 60 * 1000;
const COOKIE = "admin_session";


const K = {
  auth: "config:auth",
  providers: "config:providers",
  pools: "config:pools",
  rolemap: "config:rolemap",
  routerAuth: "config:routerAuth",
  session: "session:"
};

const DEFAULT_PROVIDERS = {
  "avalai-deepseek": {
    id: "avalai-deepseek",
    label: "AvalAI — DeepSeek V4 Flash",
    kind: "openai",
    baseUrl: "https://api.avalai.ir/v1/chat/completions",
    cfAigToken: "",
    anthropicVersion: "",
    extraHeaders: {},
    apiKeys: []
  },

  "gemini-gateway": {
    id: "gemini-gateway",
    label: "Gemini via Cloudflare AI Gateway",
    kind: "gemini",
    baseUrl:
      "https://gateway.ai.cloudflare.com/v1/4bddba13f2ca2e21c9f3d73f2d00de97/ali-gemini-proxy/google-ai-studio",
    cfAigToken: "",
    anthropicVersion: "",
    extraHeaders: {},
    apiKeys: []
  },

  "opencode-zen": {
    id: "opencode-zen",
    label: "OpenCode Zen (free)",
    kind: "openai",
    baseUrl: "https://opencode.ai/zen/v1/chat/completions",
    cfAigToken: "",
    anthropicVersion: "",
    extraHeaders: {},
    apiKeys: []
  }
};

const DEFAULT_POOLS = {
  "pool-opus": {
    id: "pool-opus",
    label: "Opus Pool",
    entries: [
      {
        providerId: "avalai-deepseek",
        model: "deepseek-v4-flash"
      }
    ],
    fallbackPoolId: ""
  },

  "pool-sonnet": {
    id: "pool-sonnet",
    label: "Sonnet Pool",
    entries: [
      {
        providerId: "gemini-gateway",
        model: "gemini-3.6-flash"
      },
      {
        providerId: "gemini-gateway",
        model: "gemini-2.5-pro"
      },
      {
        providerId: "gemini-gateway",
        model: "gemini-2.5-flash"
      }
    ],
    fallbackPoolId: ""
  },

  "pool-haiku": {
    id: "pool-haiku",
    label: "Haiku Pool",
    entries: [
      {
        providerId: "opencode-zen",
        model: "hy3-free"
      },
      {
        providerId: "opencode-zen",
        model: "nemotron-3.5-lightning-free"
      },
      {
        providerId: "opencode-zen",
        model: "laguna-s-2.1-free"
      },
      {
        providerId: "opencode-zen",
        model: "x-preview-f-free"
      },
      {
        providerId: "opencode-zen",
        model: "nemotron-3-ultra-free"
      }
    ],
    /*
     * OpenCode Zen's free models appear to share ONE rate-limit
     * bucket across the whole account, not a bucket per model —
     * so rotating between them does nothing once that shared
     * quota is spent. Falling through to the (paid, working)
     * Sonnet/Gemini pool means haiku-tier requests still get
     * answered instead of erroring out.
     */
    fallbackPoolId: "pool-sonnet"
  }
};

const DEFAULT_ROLEMAP = {
  rules: [
    {
      keyword: "opus",
      poolId: "pool-opus"
    },
    {
      keyword: "haiku",
      poolId: "pool-haiku"
    },
    {
      keyword: "sonnet",
      poolId: "pool-sonnet"
    }
  ],
  defaultPoolId: "pool-opus"
};

const j = (x, s = 200, h = {}) =>
  new Response(JSON.stringify(x), {
    status: s,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...h
    }
  });

const aerr = (
  m,
  t = "invalid_request_error",
  s = 400,
  h = {}
) =>
  j(
    {
      type: "error",
      error: {
        type: t,
        message: m
      }
    },
    s,
    h
  );

const b64 = (b) => {
  let x = "";
  for (const v of b) {
    x += String.fromCharCode(v);
  }
  return btoa(x);
};

const u8 = (s) => {
  const x = atob(s);
  const b = new Uint8Array(x.length);

  for (let i = 0; i < x.length; i++) {
    b[i] = x.charCodeAt(i);
  }

  return b;
};

const eq = (a, b) => {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let d = 0;

  for (let i = 0; i < a.length; i++) {
    d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return d === 0;
};

const mask = (k) =>
  !k || k.length < 4 ? "••••" : `••••${k.slice(-4)}`;

async function hashPassword(p, saltB64) {
  const salt = saltB64
    ? u8(saltB64)
    : crypto.getRandomValues(new Uint8Array(16));

  const km = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(p),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    km,
    256
  );

  return {
    hash: b64(new Uint8Array(bits)),
    salt: b64(salt)
  };
}




async function verifyPassword(p, h, s) {
  if (!h || !s) {
    return false;
  }

  return eq((await hashPassword(p, s)).hash, h);
}

async function kvGet(env, key, def) {
  const v = await env.CONFIG_KV.get(key, "json");
  return v ?? def;
}

const kvPut = (env, key, v) =>
  env.CONFIG_KV.put(key, JSON.stringify(v));

async function auth(env) {
  return kvGet(env, K.auth, null);
}

async function providers(env) {
  return kvGet(env, K.providers, DEFAULT_PROVIDERS);
}

async function pools(env) {
  return kvGet(env, K.pools, DEFAULT_POOLS);
}

async function rolemap(env) {
  return kvGet(env, K.rolemap, DEFAULT_ROLEMAP);
}

async function routerAuth(env) {
  return kvGet(env, K.routerAuth, {
    enabled: false,
    token: ""
  });
}

function cookie(request) {
  const c = request.headers.get("cookie") || "";
  const m = c.match(
    new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`)
  );

  return m ? m[1] : null;
}

function setCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`;
}

function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

async function newSession(env) {
  const raw = crypto.getRandomValues(new Uint8Array(32));

  const token = b64(raw).replace(
    /[^a-zA-Z0-9]/g,
    ""
  );

  const ar = await auth(env);

  const ver = Number.isInteger(ar?.sessionVersion)
    ? ar.sessionVersion
    : 0;

  await env.CONFIG_KV.put(
    K.session + token,
    JSON.stringify({
      expires: Date.now() + SESSION_TTL * 1000,
      sessionVersion: ver
    }),
    {
      expirationTtl: SESSION_TTL
    }
  );

  return token;
}

async function validSession(request, env) {
  const t = cookie(request);

  if (!t) {
    return null;
  }

  const s = await env.CONFIG_KV.get(
    K.session + t,
    "json"
  );

  const ar = await auth(env);

  if (!s || s.expires < Date.now()) {
    return null;
  }

  const ver = Number.isInteger(ar?.sessionVersion)
    ? ar.sessionVersion
    : 0;

  return s.sessionVersion === ver ? t : null;
}

function cleanHeaders(h) {
  if (
    !h ||
    typeof h !== "object" ||
    Array.isArray(h)
  ) {
    return {};
  }

  const o = {};

  for (const [k, v] of Object.entries(h)) {
    o[String(k)] = String(v);
  }

  return o;
}

function redacted(ps) {
  const o = {};

  for (const id of Object.keys(ps)) {
    const p = ps[id];

    o[id] = {
      id: p.id,
      label: p.label,
      kind: p.kind,
      baseUrl: p.baseUrl,
      hasCfAigToken: !!p.cfAigToken,
      anthropicVersion: p.anthropicVersion || "",
      extraHeaders: p.extraHeaders || {},
      apiKeyCount: Array.isArray(p.apiKeys)
        ? p.apiKeys.length
        : 0,
      apiKeysMasked: (p.apiKeys || []).map(mask)
    };
  }

  return o;
}

/* ============================================================
   LOGIN
   ============================================================ */

async function login(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const p = String(body?.password || "");
  const ar = await auth(env);
  const now = Date.now();

  if (ar?.lockUntil > now) {
    return j(
      {
        ok: false,
        error: `Too many attempts. Try again in ${Math.ceil(
          (ar.lockUntil - now) / 1000
        )}s.`
      },
      429
    );
  }

  /*
   * IMPORTANT:
   * A KV auth record may exist without a password hash because
   * a previous first-login attempt was incorrect.
   *
   * Such a state is still treated as "first login".
   */
  const fresh =
    !ar ||
    !ar.passwordHash ||
    !ar.salt;

  let ok = fresh
    ? p === DEFAULT_ADMIN_PASSWORD
    : await verifyPassword(
        p,
        ar.passwordHash,
        ar.salt
      );

  const must = fresh
    ? true
    : !!ar.mustChangePassword;

  if (!ok) {
    const n = (ar?.failedAttempts || 0) + 1;

    await kvPut(env, K.auth, {
      ...(ar || {}),
      passwordHash: ar?.passwordHash || null,
      salt: ar?.salt || null,
      mustChangePassword: true,
      failedAttempts: n,
      lockUntil:
        n >= MAX_FAILED
          ? now + LOCK_MS
          : 0,
      sessionVersion: Number.isInteger(
        ar?.sessionVersion
      )
        ? ar.sessionVersion
        : 0
    });

    return j(
      {
        ok: false,
        error: "Invalid password."
      },
      401
    );
  }

  if (ar) {
    await kvPut(env, K.auth, {
      ...ar,
      failedAttempts: 0,
      lockUntil: 0,
      sessionVersion: Number.isInteger(
        ar.sessionVersion
      )
        ? ar.sessionVersion
        : 0
    });
  }

  const token = await newSession(env);

  return j(
    {
      ok: true,
      mustChangePassword: must
    },
    200,
    {
      "Set-Cookie": setCookie(token)
    }
  );
}

/* ============================================================
   PASSWORD CHANGE
   ============================================================ */

async function changePassword(request, env) {
  let b;

  try {
    b = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const cur = String(b?.currentPassword || "");
  const next = String(b?.newPassword || "");

  if (next.length < 8) {
    return j(
      {
        ok: false,
        error:
          "New password must be at least 8 characters."
      },
      400
    );
  }

  const ar = await auth(env);

  const ok =
    !ar || !ar.passwordHash
      ? cur === DEFAULT_ADMIN_PASSWORD
      : await verifyPassword(
          cur,
          ar.passwordHash,
          ar.salt
        );

  if (!ok) {
    return j(
      {
        ok: false,
        error: "Current password is incorrect."
      },
      401
    );
  }

  const hs = await hashPassword(next);

  /*
   * Incrementing sessionVersion invalidates ALL previously
   * issued admin sessions.
   */
  const ver =
    (Number.isInteger(ar?.sessionVersion)
      ? ar.sessionVersion
      : 0) + 1;

  await kvPut(env, K.auth, {
    passwordHash: hs.hash,
    salt: hs.salt,
    mustChangePassword: false,
    failedAttempts: 0,
    lockUntil: 0,
    sessionVersion: ver
  });

  /*
   * Immediately create a fresh session for the browser which
   * just changed the password.
   */
  const token = await newSession(env);

  return j(
    {
      ok: true
    },
    200,
    {
      "Set-Cookie": setCookie(token)
    }
  );
}

async function requireChanged(env) {
  const ar = await auth(env);

  return (
    !!ar?.passwordHash &&
    !ar?.mustChangePassword
  );
}

/* ============================================================
   PROVIDERS
   ============================================================ */

async function saveProvider(request, env) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  let b;

  try {
    b = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const ps = await providers(env);

  const id =
    String(b.id || "").trim() ||
    `provider-${crypto.randomUUID().slice(0, 8)}`;

  const old = ps[id] || {};

  const kind = [
    "openai",
    "gemini",
    "anthropic"
  ].includes(b.kind)
    ? b.kind
    : "openai";

  let keys = Array.isArray(old.apiKeys)
    ? old.apiKeys
    : [];

  if (
    typeof b.apiKeysRaw === "string" &&
    b.apiKeysRaw.trim()
  ) {
    keys = b.apiKeysRaw
      .split(/[\n,]/)
      .map((x) => x.trim())
      .filter(Boolean);
  } else if (b.clearApiKeys === true) {
    keys = [];
  }

  ps[id] = {
    id,
    label: String(b.label || id),
    kind,
    baseUrl: String(b.baseUrl || ""),

    cfAigToken:
      typeof b.cfAigToken === "string" &&
      b.cfAigToken.length
        ? b.cfAigToken
        : b.clearCfAigToken
        ? ""
        : old.cfAigToken || "",

    anthropicVersion:
      String(
        b.anthropicVersion ||
          old.anthropicVersion ||
          ""
      ),

    extraHeaders: cleanHeaders(
      b.extraHeaders !== undefined
        ? b.extraHeaders
        : old.extraHeaders || {}
    ),

    apiKeys: keys
  };

  await kvPut(env, K.providers, ps);

  return j({
    ok: true,
    id
  });
}

async function deleteProvider(env, id) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  const ps = await providers(env);

  delete ps[id];

  await kvPut(env, K.providers, ps);

  return j({
    ok: true
  });
}

/* ============================================================
   POOLS
   ============================================================ */

async function savePool(request, env) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  let b;

  try {
    b = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const pl = await pools(env);

  const id =
    String(b.id || "").trim() ||
    `pool-${crypto.randomUUID().slice(0, 8)}`;

  const entries = Array.isArray(b.entries)
    ? b.entries
        .filter(
          (e) =>
            e &&
            e.providerId &&
            e.model
        )
        .map((e) => ({
          providerId: String(e.providerId),
          model: String(e.model)
        }))
    : [];

  pl[id] = {
    id,
    label: String(b.label || id),
    entries,
    fallbackPoolId: String(b.fallbackPoolId || "")
  };

  await kvPut(env, K.pools, pl);

  return j({
    ok: true,
    id
  });
}

async function deletePool(env, id) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  const pl = await pools(env);

  delete pl[id];

  /*
   * Clean up any pools that pointed their fallback at the one
   * we just deleted, so we never reference a dangling pool id.
   */
  for (const otherId of Object.keys(pl)) {
    if (pl[otherId].fallbackPoolId === id) {
      pl[otherId] = { ...pl[otherId], fallbackPoolId: "" };
    }
  }

  await kvPut(env, K.pools, pl);

  const rm = await rolemap(env);

  rm.rules = (rm.rules || []).filter(
    (r) => r.poolId !== id
  );

  if (rm.defaultPoolId === id) {
    rm.defaultPoolId =
      Object.keys(pl)[0] || "";
  }

  await kvPut(env, K.rolemap, rm);

  return j({
    ok: true
  });
}

/* ============================================================
   ROLE MAP
   ============================================================ */

async function saveRoleMap(request, env) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  let b;

  try {
    b = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const rm = {
    rules: Array.isArray(b.rules)
      ? b.rules
          .filter(
            (r) =>
              r &&
              r.keyword &&
              r.poolId
          )
          .map((r) => ({
            keyword: String(
              r.keyword
            ).toLowerCase(),
            poolId: String(r.poolId)
          }))
      : [],

    defaultPoolId: String(
      b.defaultPoolId || ""
    )
  };

  await kvPut(env, K.rolemap, rm);

  return j({
    ok: true
  });
}

/* ============================================================
   ROUTER AUTH
   ============================================================ */

async function saveRouterAuth(request, env) {
  if (!(await requireChanged(env))) {
    return aerr(
      "Change your password before editing configuration.",
      "authentication_error",
      403
    );
  }

  let b;

  try {
    b = await request.json();
  } catch {
    return aerr("Invalid JSON body.");
  }

  const enabled = !!b.enabled;
  const token = String(
    b.token || ""
  ).trim();

  if (enabled && token.length < 32) {
    return j(
      {
        ok: false,
        error:
          "Router bearer token must be at least 32 characters."
      },
      400
    );
  }

  await kvPut(env, K.routerAuth, {
    enabled,
    token
  });

  return j({
    ok: true,
    enabled,
    token
  });
}

/* ============================================================
   ADMIN ROUTER
   ============================================================ */

async function admin(request, env, url) {
  if (
    url.pathname === "/admin" &&
    request.method === "GET"
  ) {
    return new Response(
      ADMIN_HTML,
      {
        headers: {
          "content-type":
            "text/html; charset=utf-8"
        }
      }
    );
  }

  if (
    url.pathname ===
      "/admin/api/login" &&
    request.method === "POST"
  ) {
    return login(request, env);
  }

  const s = await validSession(
    request,
    env
  );

  if (!s) {
    return j(
      {
        ok: false,
        error: "Not authenticated."
      },
      401
    );
  }

  if (
    url.pathname ===
      "/admin/api/logout" &&
    request.method === "POST"
  ) {
    await env.CONFIG_KV.delete(
      K.session + s
    );

    return j(
      {
        ok: true
      },
      200,
      {
        "Set-Cookie": clearCookie()
      }
    );
  }

  if (
    url.pathname ===
      "/admin/api/change-password" &&
    request.method === "POST"
  ) {
    return changePassword(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/admin/api/state" &&
    request.method === "GET"
  ) {
    const ar = await auth(env);

    const [
      ps,
      pl,
      rm,
      ra
    ] = await Promise.all([
      providers(env),
      pools(env),
      rolemap(env),
      routerAuth(env)
    ]);

    return j({
      mustChangePassword:
        !ar?.passwordHash ||
        !!ar?.mustChangePassword,

      providers: redacted(ps),
      pools: pl,
      roleMap: rm,
      routerAuth: ra
    });
  }

  if (
    url.pathname ===
      "/admin/api/providers" &&
    request.method === "POST"
  ) {
    return saveProvider(
      request,
      env
    );
  }

  if (
    url.pathname.startsWith(
      "/admin/api/providers/"
    ) &&
    request.method === "DELETE"
  ) {
    return deleteProvider(
      env,
      decodeURIComponent(
        url.pathname.split("/").pop()
      )
    );
  }

  if (
    url.pathname ===
      "/admin/api/pools" &&
    request.method === "POST"
  ) {
    return savePool(
      request,
      env
    );
  }

  if (
    url.pathname.startsWith(
      "/admin/api/pools/"
    ) &&
    request.method === "DELETE"
  ) {
    return deletePool(
      env,
      decodeURIComponent(
        url.pathname.split("/").pop()
      )
    );
  }

  if (
    url.pathname ===
      "/admin/api/rolemap" &&
    request.method === "POST"
  ) {
    return saveRoleMap(
      request,
      env
    );
  }

  if (
    url.pathname ===
      "/admin/api/router-auth" &&
    request.method === "POST"
  ) {
    return saveRouterAuth(
      request,
      env
    );
  }

  return new Response(
    "Not Found",
    {
      status: 404
    }
  );
}

/* ============================================================
   CLAUDE / OPENAI CONVERSION
   ============================================================ */

function systemText(s) {
  if (!s) {
    return "";
  }

  if (typeof s === "string") {
    return s;
  }

  if (Array.isArray(s)) {
    return s
      .map((p) =>
        typeof p === "string"
          ? p
          : p?.type === "text"
          ? p.text || ""
          : ""
      )
      .filter(Boolean)
      .join("\n");
  }

  return String(s);
}

function blockText(p) {
  if (!p) {
    return "";
  }

  if (p.type === "text") {
    return p.text || "";
  }

  if (p.type === "image") {
    return "[image content]";
  }

  return JSON.stringify(p);
}

function toOpenAIMessages(ms) {
  const out = [];

  for (const m of ms || []) {
    if (typeof m.content === "string") {
      out.push({
        role: m.role,
        content: m.content
      });

      continue;
    }

    if (!Array.isArray(m.content)) {
      out.push({
        role: m.role,
        content: String(
          m.content ?? ""
        )
      });

      continue;
    }

    if (m.role === "user") {
      const t = [];
      const tr = [];

      for (const p of m.content || []) {
        if (!p) {
          continue;
        }

        if (p.type === "text") {
          t.push(p.text || "");
        }

        else if (
          p.type === "tool_result"
        ) {
          tr.push({
            role: "tool",
            tool_call_id:
              p.tool_use_id,

            content:
              typeof p.content ===
              "string"
                ? p.content
                : JSON.stringify(
                    p.content ?? ""
                  )
          });
        }

        else {
          t.push(blockText(p));
        }
      }

      if (t.length) {
        out.push({
          role: "user",
          content: t.join("\n")
        });
      }

      out.push(...tr);

      continue;
    }

    if (m.role === "assistant") {
      const t = [];
      const tc = [];

      for (const p of m.content || []) {
        if (!p) {
          continue;
        }

        if (p.type === "text") {
          t.push(p.text || "");
        }

        else if (
          p.type === "tool_use"
        ) {
          tc.push({
            id:
              p.id ||
              `tool_${crypto.randomUUID()}`,

            type: "function",

            function: {
              name: p.name || "",

              arguments:
                JSON.stringify(
                  p.input ?? {}
                )
            }
          });
        }

        else {
          t.push(blockText(p));
        }
      }

      const x = {
        role: "assistant",
        content:
          t.length
            ? t.join("\n")
            : null
      };

      if (tc.length) {
        x.tool_calls = tc;
      }

      out.push(x);

      continue;
    }

    out.push({
      role: m.role,
      content:
        JSON.stringify(m.content)
    });
  }

  return out;
}

function toOpenAITools(ts) {
  if (!Array.isArray(ts)) {
    return undefined;
  }

  return ts
    .filter(
      (t) => t && t.name
    )
    .map((t) => ({
      type: "function",

      function: {
        name: t.name,
        description:
          t.description || "",

        parameters:
          t.input_schema || {
            type: "object",
            properties: {}
          }
      }
    }));
}

function toolChoice(x) {
  if (!x) {
    return undefined;
  }

  if (x.type === "auto") {
    return "auto";
  }

  if (x.type === "any") {
    return "required";
  }

  if (
    x.type === "tool" &&
    x.name
  ) {
    return {
      type: "function",
      function: {
        name: x.name
      }
    };
  }

  return undefined;
}

function textFromOpenAI(m) {
  if (!m) {
    return "";
  }

  if (
    typeof m.content ===
    "string"
  ) {
    return m.content;
  }

  if (Array.isArray(m.content)) {
    return m.content
      .map((x) =>
        typeof x === "string"
          ? x
          : x?.type === "text"
          ? x.text || ""
          : ""
      )
      .join("");
  }

  return "";
}

function fromOpenAI(
  r,
  requested,
  backend
) {
  const c =
    r?.choices?.[0];

  if (!c) {
    throw Error(
      "Provider returned no choices."
    );
  }

const m =
  c.message || {};

const hasText =
  typeof m.content === "string"
    ? m.content.length > 0
    : Array.isArray(m.content) &&
      m.content.some(
        (x) =>
          typeof x === "string"
            ? x.length > 0
            : x?.type === "text" &&
              typeof x.text === "string" &&
              x.text.length > 0
      );

const hasTools =
  Array.isArray(m.tool_calls) &&
  m.tool_calls.length > 0;

if (!hasText && !hasTools) {
  throw Error(
    "Provider returned an empty assistant response."
  );
}

const content = [];

  const t =
    textFromOpenAI(m);

  if (t) {
    content.push({
      type: "text",
      text: t
    });
  }

  for (
    const tc of
      m.tool_calls || []
  ) {
    let input = {};

    try {
      input = JSON.parse(
        tc?.function?.arguments ||
          "{}"
      );
    } catch {}

    content.push({
      type: "tool_use",

      id:
        tc.id ||
        `tool_${crypto.randomUUID()}`,

      name:
        tc?.function?.name || "",

      input
    });
  }

  return {
    id:
      r.id ||
      `msg_${crypto.randomUUID()}`,

    type: "message",
    role: "assistant",
    model: requested,
    content,

    stop_reason:
      c.finish_reason ===
      "tool_calls"
        ? "tool_use"
        : c.finish_reason ===
          "length"
        ? "max_tokens"
        : "end_turn",

    stop_sequence: null,

    usage: {
      input_tokens:
        r?.usage?.prompt_tokens ||
        0,

      output_tokens:
        r?.usage?.completion_tokens ||
        0
    },

    _backend_model:
      backend
  };
}

/* ============================================================
   GEMINI
   ============================================================ */

function geminiMessages(ms) {
  const out = [];

  for (const m of ms || []) {
    const c = m.content;

    if (typeof c === "string") {
      out.push({
        role:
          m.role === "assistant"
            ? "model"
            : "user",

        parts: [
          {
            text: c
          }
        ]
      });

      continue;
    }

    if (!Array.isArray(c)) {
      continue;
    }

    if (m.role === "user") {
      const parts = [];

      for (
        const p of c
      ) {
        if (!p) {
          continue;
        }

        if (p.type === "text") {
          parts.push({
            text: p.text || ""
          });
        }

        else if (
          p.type ===
          "tool_result"
        ) {
          parts.push({
            functionResponse: {
              name:
                p.name ||
                p.tool_use_id ||
                "tool",

              response: {
                result:
                  typeof p.content ===
                  "string"
                    ? p.content
                    : JSON.stringify(
                        p.content ??
                          ""
                      )
              }
            }
          });
        }

        else if (
          p.type === "image"
        ) {
          parts.push({
            text: "[image content]"
          });
        }
      }

      if (parts.length) {
        out.push({
          role: "user",
          parts
        });
      }
    }

    else if (
      m.role ===
      "assistant"
    ) {
      const parts = [];

      for (
        const p of c
      ) {
        if (!p) {
          continue;
        }

        if (p.type === "text") {
          parts.push({
            text: p.text || ""
          });
        }

        else if (
          p.type ===
          "tool_use"
        ) {
          parts.push({
            functionCall: {
              name: p.name,
              args:
                p.input || {}
            }
          });
        }
      }

      if (parts.length) {
        out.push({
          role: "model",
          parts
        });
      }
    }
  }

  return out;
}

function geminiTools(ts) {
  if (
    !Array.isArray(ts) ||
    !ts.length
  ) {
    return undefined;
  }

  return [
    {
      functionDeclarations:
        ts
          .filter(
            (t) =>
              t && t.name
          )
          .map((t) => ({
            name: t.name,
            description:
              t.description || "",

            parameters:
              t.input_schema || {
                type: "object",
                properties: {}
              }
          }))
    }
  ];
}

function fromGemini(
  r,
  requested
) {
  const c =
    r?.candidates?.[0];

  if (!c) {
    throw Error(
      "Gemini returned no candidates."
    );
  }
  const parts =
  c?.content?.parts || [];

if (!parts.length) {
  throw Error(
    "Gemini returned an empty response."
  );
}


  const content = [];

  for (
    const p of
      c?.content?.parts || []
  ) {
    if (
      typeof p.text ===
      "string"
    ) {
      content.push({
        type: "text",
        text: p.text
      });
    }

    else if (
      p.functionCall
    ) {
      content.push({
        type: "tool_use",

        id:
          `tool_${crypto.randomUUID()}`,

        name:
          p.functionCall.name,

        input:
          p.functionCall.args ||
          {}
      });
    }
  }

  return {
    id:
      `msg_${crypto.randomUUID()}`,

    type: "message",
    role: "assistant",
    model: requested,
    content,

    stop_reason:
      (
        c?.content?.parts || []
      ).some(
        (p) =>
          p.functionCall
      )
        ? "tool_use"
        : c.finishReason ===
          "MAX_TOKENS"
        ? "max_tokens"
        : "end_turn",

    stop_sequence: null,

    usage: {
      input_tokens:
        r?.usageMetadata
          ?.promptTokenCount ||
        0,

      output_tokens:
        r?.usageMetadata
          ?.candidatesTokenCount ||
        0
    }
  };
}

/* ============================================================
   ERROR / FALLBACK
   ============================================================ */

function shouldFallback(
  status,
  text
) {
  const x =
    String(text || "")
      .toLowerCase();

  return (
    status === 429 ||
    status >= 500 ||
    status === 401 ||
    status === 403 ||
    status === 404 ||

    x.includes(
      "freeusagelimiterror"
    ) ||

    x.includes(
      "model unavailable"
    ) ||

    x.includes(
      "not found for api"
    ) ||

    x.includes(
      "api key not valid"
    ) ||

    x.includes(
      "permission_denied"
    ) ||

    x.includes(
      "invalid authentication credentials"
    ) ||

    x.includes(
      "rate limit exceeded"
    ) ||

    x.includes(
      "temporarily unavailable"
    )
  );
}

/* ============================================================
   PROVIDER CALLS
   ============================================================ */

async function callProvider(
  provider,
  model,
  key,
  body,
  ms,
  tools
) {
  /*
   * ==========================================================
   * CLOUDFLARE AI GATEWAY COMPATIBILITY ENDPOINT
   *
   * This path is used when a provider points at:
   *
   *   /compat/chat/completions
   *
   * It uses the OpenAI-compatible request format.
   *
   * Cloudflare Gateway authentication:
   *
   *   cf-aig-authorization: Bearer <CF_GATEWAY_TOKEN>
   *
   * Provider authentication:
   *
   *   Authorization: Bearer <PROVIDER_API_KEY>
   *
   * This is intentionally checked BEFORE provider.kind so that
   * a provider saved as "gemini" can still use the Cloudflare
   * compatibility endpoint correctly.
   * ==========================================================
   */

  const baseUrl =
    String(
      provider.baseUrl || ""
    );

  const isCloudflareCompat =
    baseUrl.includes(
      "/compat/chat/completions"
    );


  if (isCloudflareCompat) {

const h = {
  "Content-Type": "application/json"
};


    /*
     * Cloudflare AI Gateway authentication.
     */
    if (
      provider.cfAigToken
    ) {
      h[
        "cf-aig-authorization"
      ] =
        "Bearer " +
        provider.cfAigToken;
    }


    /*
     * Provider authentication.
     *
     * For Google AI Studio this is the Google
     * API key.
     *
     * For another OpenAI-compatible provider this
     * can be its normal bearer credential.
     */
 

if (key) {
  h.Authorization =
    "Bearer " +
    key;
}

    /*
     * User-defined custom headers.
     */
    Object.assign(
      h,
      cleanHeaders(
        provider.extraHeaders
      )
    );


    const payload = {
      model,
      messages:
        toOpenAIMessages(ms),
      stream: false
    };


    if (
      body.max_tokens !==
      undefined
    ) {
      payload.max_tokens =
        body.max_tokens;
    }


    if (
      body.temperature !==
      undefined
    ) {
      payload.temperature =
        body.temperature;
    }


    if (
      body.top_p !==
      undefined
    ) {
      payload.top_p =
        body.top_p;
    }


    if (
      Array.isArray(tools) &&
      tools.length
    ) {
      payload.tools =
        tools;

      const tc =
        toolChoice(
          body.tool_choice
        );

      if (
        tc !== undefined
      ) {
        payload.tool_choice =
          tc;
      }
    }


    return fetch(
      baseUrl,
      {
        method: "POST",
        headers: h,
        body:
          JSON.stringify(
            payload
          )
      }
    );
  }


  /*
   * ==========================================================
   * GEMINI NATIVE ENDPOINT
   *
   * Kept for providers explicitly using the native Gemini
   * Google AI Studio format rather than /compat/chat/completions.
   * ==========================================================
   */

  if (
    provider.kind ===
    "gemini"
  ) {

    const url =
      `${baseUrl.replace(
        /\/$/,
        ""
      )}/v1beta/models/${encodeURIComponent(
        model
      )}:generateContent`;


    const payload = {
      contents:
        geminiMessages(ms)
    };


    const sys =
      systemText(
        body.system
      );

    if (sys) {
      payload.systemInstruction =
        {
          parts: [
            {
              text: sys
            }
          ]
        };
    }


    const gt =
      geminiTools(
        body.tools
      );

    if (gt) {
      payload.tools = gt;
    }


    payload.generationConfig =
      {};


    if (
      body.max_tokens !==
      undefined
    ) {
      payload
        .generationConfig
        .maxOutputTokens =
        body.max_tokens;
    }


    if (
      body.temperature !==
      undefined
    ) {
      payload
        .generationConfig
        .temperature =
        body.temperature;
    }


    if (
      body.top_p !==
      undefined
    ) {
      payload
        .generationConfig
        .topP =
        body.top_p;
    }


    const h = {
      "Content-Type":
        "application/json"
    };


    if (
      provider.cfAigToken
    ) {
      h[
        "cf-aig-authorization"
      ] =
        "Bearer " +
        provider.cfAigToken;
    }


    if (key) {
      h[
        "x-goog-api-key"
      ] = key;
    }


    Object.assign(
      h,
      cleanHeaders(
        provider.extraHeaders
      )
    );


    return fetch(
      url,
      {
        method: "POST",
        headers: h,
        body:
          JSON.stringify(
            payload
          )
      }
    );
  }


  /*
   * ==========================================================
   * ANTHROPIC-COMPATIBLE PROVIDER
   * ==========================================================
   */

  if (
    provider.kind ===
    "anthropic"
  ) {

    const h = {
      "Content-Type":
        "application/json",

      "anthropic-version":
        provider.anthropicVersion ||
        "2023-06-01"
    };


    if (key) {
      h["x-api-key"] =
        key;
    }


    if (
      provider.cfAigToken
    ) {
      h[
        "cf-aig-authorization"
      ] =
        "Bearer " +
        provider.cfAigToken;
    }


    Object.assign(
      h,
      cleanHeaders(
        provider.extraHeaders
      )
    );


    const payload = {
      ...body,
      model,
      stream: false
    };


    delete payload.__internal;


    return fetch(
      baseUrl,
      {
        method: "POST",
        headers: h,
        body:
          JSON.stringify(
            payload
          )
      }
    );
  }


/*
 * ============================================================
 * NORMAL OPENAI-COMPATIBLE PROVIDER
 * ============================================================
 */

const h = {
  "Content-Type": "application/json"
};

if (key) {
  h.Authorization = "Bearer " + key;
}

/*
 * Optional custom headers configured in the Admin UI.
 *
 * Example:
 * {
 *   "User-Agent": "opencode/1.18.18"
 * }
 *
 * This keeps provider-specific behavior configurable
 * instead of hardcoded into the Worker.
 */
Object.assign(
  h,
  cleanHeaders(provider.extraHeaders)
);

const payload = {
  model,
  messages: toOpenAIMessages(ms),
  stream: false
};

if (body.max_tokens !== undefined) {
  payload.max_tokens = body.max_tokens;
}

if (body.temperature !== undefined) {
  payload.temperature = body.temperature;
}

if (body.top_p !== undefined) {
  payload.top_p = body.top_p;
}

if (
  Array.isArray(tools) &&
  tools.length
) {
  payload.tools = tools;

  const tc = toolChoice(body.tool_choice);

  if (tc !== undefined) {
    payload.tool_choice = tc;
  }
}

return fetch(
  baseUrl,
  {
    method: "POST",
    headers: h,
    body: JSON.stringify(payload)
  }
);

}
async function callWithKeys(
  provider,
  model,
  body,
  ms,
  tools
) {
  const keys =
    Array.isArray(provider.apiKeys) &&
    provider.apiKeys.length
      ? provider.apiKeys
      : [null];

  const attempts = [];
  let last = null;

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];

    try {
      const r = await callProvider(
        provider,
        model,
        key,
        body,
        ms,
        tools
      );

      const text = await r.text();
      const retryAfter =
        r.headers.get("retry-after") ||
        null;

      last = {
        ok: r.ok,
        status: r.status,
        text,
        contentType:
          r.headers.get("content-type"),
        keyIndex: i,
        retryAfter
      };

      attempts.push({
        keyIndex: i,
        status: r.status,
        ok: r.ok
      });

      /*
       * Successful HTTP response.
       *
       * IMPORTANT:
       * We return it to the pool router, which is responsible
       * for validating/parsing the actual provider payload.
       */
      if (r.ok) {
        return {
          ...last,
          attempts
        };
      }

      /*
       * HTTP failure.
       *
       * If this error is considered retryable, try the next key.
       */
      if (
        shouldFallback(
          r.status,
          text
        )
      ) {
        continue;
      }

      /*
       * Non-retryable failure:
       * stop rotating keys for this provider.
       */
      return {
        ...last,
        attempts
      };

    } catch (err) {
      last = {
        ok: false,
        status: 502,
        text:
          err?.message ||
          "Provider request failed.",
        contentType:
          "application/json",
        keyIndex: i,
        retryAfter: null
      };

      attempts.push({
        keyIndex: i,
        status: 502,
        ok: false,
        error:
          err?.message ||
          "Provider request failed."
      });

      /*
       * Network/fetch exception:
       * try the next key.
       */
      continue;
    }
  }

  return {
    ...(last || {
      ok: false,
      status: 502,
      text: "All provider keys failed.",
      contentType:
        "application/json",
      retryAfter: null
    }),
    attempts
  };
}
function fromAnthropic(
  r,
  requested
) {
  return {
    id:
      r.id ||
      `msg_${crypto.randomUUID()}`,

    type: "message",
    role: "assistant",
    model: requested,

    content:
      r.content || [],

    stop_reason:
      r.stop_reason ||
      "end_turn",

    stop_sequence:
      r.stop_sequence ??
      null,

    usage: {
      input_tokens:
        r?.usage
          ?.input_tokens ||
        0,

      output_tokens:
        r?.usage
          ?.output_tokens ||
        0
    }
  };
}

/* ============================================================
   ANTHROPIC SSE
   ============================================================ */

function sse(msg) {
  const ev = [];

  ev.push([
    "message_start",
    {
      type:
        "message_start",

      message: {
        id: msg.id,
        type: "message",
        role: "assistant",
        model: msg.model,
        content: [],

        stop_reason:
          null,

        stop_sequence:
          null,

        usage: {
          input_tokens:
            msg.usage
              .input_tokens,

          output_tokens: 0
        }
      }
    }
  ]);

  msg.content.forEach(
    (b, i) => {
      if (
        b.type === "text"
      ) {
        ev.push([
          "content_block_start",
          {
            type:
              "content_block_start",

            index: i,

            content_block: {
              type: "text",
              text: ""
            }
          }
        ]);

        ev.push([
          "content_block_delta",
          {
            type:
              "content_block_delta",

            index: i,

            delta: {
              type:
                "text_delta",

              text:
                b.text || ""
            }
          }
        ]);

        ev.push([
          "content_block_stop",
          {
            type:
              "content_block_stop",

            index: i
          }
        ]);
      }

      else if (
        b.type ===
        "tool_use"
      ) {
        ev.push([
          "content_block_start",
          {
            type:
              "content_block_start",

            index: i,

            content_block: {
              type:
                "tool_use",

              id: b.id,
              name: b.name,
              input: {}
            }
          }
        ]);

        ev.push([
          "content_block_delta",
          {
            type:
              "content_block_delta",

            index: i,

            delta: {
              type:
                "input_json_delta",

              partial_json:
                JSON.stringify(
                  b.input || {}
                )
            }
          }
        ]);

        ev.push([
          "content_block_stop",
          {
            type:
              "content_block_stop",

            index: i
          }
        ]);
      }
    }
  );

  ev.push([
    "message_delta",
    {
      type:
        "message_delta",

      delta: {
        stop_reason:
          msg.stop_reason,

        stop_sequence:
          null
      },

      usage: {
        output_tokens:
          msg.usage
            .output_tokens
      }
    }
  ]);

  ev.push([
    "message_stop",
    {
      type:
        "message_stop"
    }
  ]);

  return ev
    .map(
      (e) =>
        `event: ${e[0]}\ndata: ${JSON.stringify(
          e[1]
        )}\n\n`
    )
    .join("");
}



  function resolvePoolId(requested, rm, poolsConfig) {
  const name =
    String(requested || "").toLowerCase();

  const rules = Array.isArray(rm?.rules)
    ? rm.rules
    : [];

  const matches = rules
    .filter(
      (r) =>
        r &&
        r.keyword &&
        r.poolId &&
        name.includes(
          String(r.keyword).toLowerCase()
        )
    )
    .sort(
      (a, b) =>
        String(b.keyword).length -
        String(a.keyword).length
    );

  for (const r of matches) {
    if (poolsConfig?.[r.poolId]) {
      return r.poolId;
    }
  }

  if (
    rm?.defaultPoolId &&
    poolsConfig?.[rm.defaultPoolId]
  ) {
    return rm.defaultPoolId;
  }

  return (
    Object.keys(poolsConfig || {})[0] ||
    ""
  );
}

/* ============================================================
   MAIN ROUTER

   Tries every entry in the resolved pool, in order. If EVERY
   entry in that pool fails with a retryable error (rate limit,
   bad key, dead model, etc.), and that pool has a
   fallbackPoolId configured, the router moves on to that pool
   and tries its entries too — and so on, until something
   succeeds, a pool has no further fallback, or a pool we've
   already visited would be revisited (cycle guard).

   This is what actually fixes "a whole tier is exhausted":
   rotating providers/models WITHIN one pool can't help when
   they all share one quota (e.g. one free-tier account), but
   moving to a different pool backed by different credentials
   can.
   ============================================================ */

async function router(request, env) {
  const ra = await routerAuth(env);

  /*
   * Optional protection for /v1/messages.
   */
  if (ra.enabled) {
    const authHeader =
      request.headers.get("authorization") || "";

    if (
      !/^Bearer\s+\S+$/i.test(authHeader) ||
      authHeader.slice(7).trim() !== ra.token
    ) {
      return aerr(
        "Unauthorized.",
        "authentication_error",
        401
      );
    }
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return aerr(
      "Invalid JSON request body."
    );
  }

  const requested = String(
    body.model || "default"
  );

  const [
    ps,
    pls,
    rm
  ] = await Promise.all([
    providers(env),
    pools(env),
    rolemap(env)
  ]);

  const startPoolId = resolvePoolId(
    requested,
    rm,
    pls
  );

  if (!startPoolId) {
    return aerr(
      `No pool configured for model "${requested}".`
    );
  }

  const ms = body.messages || [];

  const tools = toOpenAITools(
    body.tools
  );

  let lastStatus = 503;
  let lastRetryAfter = null;

  const attempts = [];
  const visitedPools = new Set();
  let currentPoolId = startPoolId;

  while (
    currentPoolId &&
    !visitedPools.has(currentPoolId)
  ) {
    visitedPools.add(currentPoolId);

    const pool = pls[currentPoolId];

    if (
      !pool ||
      !Array.isArray(pool.entries) ||
      !pool.entries.length
    ) {
      currentPoolId =
        pool?.fallbackPoolId || null;
      continue;
    }

    /*
     * Try every pool entry in order.
     */
    for (
      let index = 0;
      index < pool.entries.length;
      index++
    ) {
      const e = pool.entries[index];

      const providerId = String(
        e?.providerId || ""
      );

      const backendModel = String(
        e?.model || ""
      );

      /*
       * Invalid pool entry.
       */
      if (!providerId || !backendModel) {
        attempts.push({
          pool: currentPoolId,
          index,
          providerId,
          model: backendModel,
          status: 400,
          error: "Invalid pool entry."
        });

        lastStatus = 400;
        continue;
      }

      /*
       * Provider does not exist.
       */
      const p = ps[providerId];

      if (!p) {
        attempts.push({
          pool: currentPoolId,
          index,
          providerId,
          model: backendModel,
          status: 502,
          error:
            `Provider "${providerId}" is not configured.`
        });

        lastStatus = 502;
        continue;
      }

      let r;

      /*
       * Call provider.
       */
      try {
        r = await callWithKeys(
          p,
          backendModel,
          body,
          ms,
          tools
        );
      } catch (err) {
        const msg =
          err?.message ||
          "Provider request failed.";

        attempts.push({
          pool: currentPoolId,
          index,
          providerId,
          model: backendModel,
          status: 502,
          error: msg
        });

        lastStatus = 502;
        continue;
      }

      if (r?.retryAfter) {
        lastRetryAfter = r.retryAfter;
      }

      /*
       * Record attempt.
       */
      attempts.push({
        pool: currentPoolId,
        index,
        providerId,
        model: backendModel,
        status: r?.status || 502,
        ok: !!r?.ok,
        error:
          !r?.ok
            ? String(
                r?.text || ""
              ).slice(0, 500)
            : undefined
      });

      /*
       * HTTP failure.
       *
       * Retry the NEXT pool entry when retryable.
       */
      if (!r?.ok) {
        lastStatus =
          r?.status || 502;

        if (
          shouldFallback(
            r?.status,
            r?.text
          )
        ) {
          continue;
        }

        return new Response(
          r.text,
          {
            status:
              r.status || 502,
            headers: {
              "content-type":
                r.contentType ||
                "application/json",

              "X-Backend-Provider":
                providerId,

              "X-Backend-Model":
                backendModel,

              "X-Backend-Pool":
                currentPoolId
            }
          }
        );
      }

      /*
       * HTTP success.
       *
       * Still validate the provider payload.
       */
      let parsed;

      try {
        parsed = JSON.parse(
          r.text
        );
      } catch {
        lastStatus = 502;

        attempts.push({
          pool: currentPoolId,
          index,
          providerId,
          model: backendModel,
          status: 502,
          error:
            `${providerId}/${backendModel} returned invalid JSON.`
        });

        continue;
      }

      /*
       * Convert provider response
       * into Anthropic-compatible format.
       */
      let msg;

      try {
        if (p.kind === "gemini") {
          msg = fromGemini(
            parsed,
            requested
          );
        }
        else if (
          p.kind === "anthropic"
        ) {
          msg = fromAnthropic(
            parsed,
            requested
          );
        }
        else {
          msg = fromOpenAI(
            parsed,
            requested,
            backendModel
          );
        }

      } catch (err) {
        lastStatus = 502;

        attempts.push({
          pool: currentPoolId,
          index,
          providerId,
          model: backendModel,
          status: 502,
          error:
            `${providerId}/${backendModel}: ${
              err?.message ||
              "Invalid provider response."
            }`
        });

        /*
         * IMPORTANT:
         *
         * A malformed 200 response also causes
         * failover to the next pool entry.
         */
        continue;
      }

      /*
       * SUCCESS
       */
      const headers = {
        "X-Backend-Provider":
          providerId,

        "X-Backend-Model":
          backendModel,

        "X-Backend-Pool":
          currentPoolId,

        "X-Router-Attempt":
          String(attempts.length),

        "X-Router-Attempts":
          String(attempts.length)
      };

      /*
       * Convert to SSE when Claude requested streaming.
       *
       * Note: the upstream request is still sent non-streaming;
       * sse() converts the completed response into Anthropic SSE.
       */
      if (
        body.stream === true
      ) {
        return new Response(
          sse(msg),
          {
            status: 200,
            headers: {
              "content-type":
                "text/event-stream",

              "cache-control":
                "no-cache",

              ...headers
            }
          }
        );
      }

      return j(
        msg,
        200,
        headers
      );
    }

    /*
     * Every entry in this pool failed (retryably). Move on to
     * this pool's configured fallback pool, if any. The
     * visitedPools guard above prevents cycles.
     */
    currentPoolId =
      pool.fallbackPoolId || null;
  }

  /*
   * Nothing worked, anywhere in the fallback chain.
   */
  const summary =
    attempts
      .map((a) => {
        const poolTag =
          a.pool
            ? `[${a.pool}] `
            : "";

        const provider =
          a.providerId || "?";

        const model =
          a.model || "?";

        const status =
          a.status || "?";

        const error =
          a.error
            ? String(
                a.error
              ).slice(0, 300)
            : "";

        return (
          `${poolTag}${provider}/${model} → ${status}` +
          (
            error
              ? ` → ${error}`
              : ""
          )
        );
      })
      .join(" | ");

  const finalHeaders = {};

  if (lastStatus === 429) {
    finalHeaders["Retry-After"] =
      lastRetryAfter || "30";
  }

  return aerr(
    `All models failed (starting pool "${startPoolId}"). ` +
    `Attempts: ${summary}`,
    "upstream_error",
    lastStatus,
    finalHeaders
  );
}
/* ============================================================
   ADMIN PANEL
   ============================================================ */

const ADMIN_HTML = [
  "<!doctype html>",
  "<html lang=\"en\">",
  "<head>",
  "<meta charset=\"utf-8\">",
  "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
  "<title>JBRouter Admin</title>",
  "<style>",
  "@import url('https://cdnjs.cloudflare.com/ajax/libs/inter-ui/3.19.3/inter.css');",
  ":root{",
  "  --bg:#0b0d12; --bg2:#0f1218; --panel:#161a22; --panel2:#1c212b; --panel3:#20262f;",
  "  --border:#262c38; --border2:#323a48;",
  "  --text:#eef1f6; --muted:#8b93a3; --muted2:#6b7385;",
  "  --accent:#6d8bff; --accent2:#5573e0; --accent-soft:rgba(109,139,255,.12);",
  "  --danger:#ff6b72; --danger-soft:rgba(255,107,114,.12);",
  "  --success:#42d392; --success-soft:rgba(66,211,146,.12);",
  "  --warn:#f0b95a; --warn-soft:rgba(240,185,90,.12);",
  "  --radius:12px; --radius-sm:8px;",
  "  --shadow:0 8px 28px -8px rgba(0,0,0,.55);",
  "  font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;",
  "}",
  "*{box-sizing:border-box}",
  "html{background:var(--bg)}",
  "body{margin:0;background:radial-gradient(1200px 600px at 20% -10%, #151a2c 0%, var(--bg) 55%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}",
  "button,input,textarea,select{font:inherit;color:inherit}",
  "button{cursor:pointer;transition:background .15s ease,border-color .15s ease,transform .05s ease}",
  "button:active{transform:translateY(1px)}",
  "h2,h3{margin:0 0 4px;font-weight:650;letter-spacing:-.01em}",
  ".center{min-height:100vh;display:grid;place-items:center;padding:24px}",
  ".card,.item{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow)}",
  ".item{margin-bottom:16px;transition:border-color .15s ease}",
  ".item:hover{border-color:var(--border2)}",
  ".login{width:100%;max-width:400px}",
  ".login h2{font-size:20px}",
  ".brand{display:flex;align-items:center;gap:10px;margin-bottom:6px}",
  ".brand .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 4px var(--accent-soft)}",
  ".wide{max-width:1120px;margin:auto}",
  ".hide{display:none}",
  ".top{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--border);background:rgba(22,26,34,.7);backdrop-filter:blur(8px);position:sticky;top:0;z-index:5}",
  ".top b{font-size:14.5px;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}",
  ".tabs{display:flex;gap:6px;padding:18px 20px 0;max-width:1120px;margin:auto;flex-wrap:wrap}",
  ".tab{padding:9px 15px;border:1px solid transparent;border-radius:9px;color:var(--muted);cursor:pointer;font-size:13.5px;font-weight:500;transition:all .15s ease}",
  ".tab:hover{color:var(--text)}",
  ".tab.active{background:var(--panel);border-color:var(--border);color:#fff;box-shadow:var(--shadow)}",
  ".sec{display:none;padding:22px 20px 60px}.sec.active{display:block;animation:fade .18s ease}",
  "@keyframes fade{from{opacity:0;transform:translateY(2px)}to{opacity:1;transform:none}}",
  "label{display:block;color:var(--muted);font-size:12.5px;font-weight:500;margin:14px 0 6px;letter-spacing:.01em}",
  "input,textarea,select{width:100%;background:var(--panel3);color:#fff;border:1px solid var(--border2);border-radius:var(--radius-sm);padding:10px 12px;font-size:13.5px;transition:border-color .15s ease,box-shadow .15s ease}",
  "textarea{min-height:80px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;resize:vertical}",
  "input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}",
  "input::placeholder,textarea::placeholder{color:var(--muted2)}",
  ".grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 16px}@media(max-width:760px){.grid{grid-template-columns:1fr}}",
  ".row{display:flex;gap:8px;align-items:center;margin:8px 0}.row>*{flex:1}",
  ".actions{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}",
  ".primary{background:linear-gradient(180deg,var(--accent),var(--accent2));color:#fff;border:0;border-radius:var(--radius-sm);padding:10px 16px;font-weight:600;font-size:13.5px}",
  ".primary:hover{filter:brightness(1.08)}",
  ".secondary{background:var(--panel3);color:#fff;border:1px solid var(--border2);border-radius:var(--radius-sm);padding:10px 16px;font-weight:500;font-size:13.5px}",
  ".secondary:hover{border-color:var(--accent)}",
  ".danger{background:transparent;color:var(--danger);border:1px solid var(--danger);border-radius:var(--radius-sm);padding:7px 11px;font-size:12.5px;font-weight:500}",
  ".danger:hover{background:var(--danger-soft)}",
  ".muted{color:var(--muted);font-size:12.5px;line-height:1.5}",
  ".ok{color:var(--success);font-size:13px;min-height:16px}",
  ".err{color:var(--danger);font-size:13px;min-height:16px}",
  ".title{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}",
  ".title input{font-weight:650;font-size:14.5px;background:transparent;border:1px solid transparent;padding:2px 4px;margin-left:-4px;border-radius:6px}",
  ".title input:hover{border-color:var(--border2)}",
  ".id{color:var(--muted2);font:11.5px ui-monospace,monospace;margin-top:4px;display:flex;align-items:center;gap:6px}",
  ".pill{font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;border:1px solid var(--border2);background:var(--panel3);border-radius:999px;padding:2px 8px;color:var(--muted)}",
  ".section-note{margin:8px 0 20px;max-width:640px}",
  ".codebox{background:#0d1016;border:1px solid var(--border2);border-radius:var(--radius-sm);padding:11px 13px;font:12px ui-monospace,monospace;overflow-wrap:anywhere;color:#a9e6c4}",
  ".empty{color:var(--muted2);font-size:13px;border:1px dashed var(--border2);border-radius:var(--radius-sm);padding:22px;text-align:center;margin-bottom:14px}",
  ".check{display:flex;align-items:center;gap:9px;margin:14px 0;font-size:13.5px;color:var(--text)}",
  ".check input{width:auto;accent-color:var(--accent);cursor:pointer}",
  "hr.sep{border:0;border-top:1px solid var(--border);margin:18px 0}",
  "::-webkit-scrollbar{width:10px;height:10px}",
  "::-webkit-scrollbar-thumb{background:var(--border2);border-radius:8px}",
  "::-webkit-scrollbar-track{background:transparent}",
  "</style>",
  "</head>",
  "<body>",
  "<div id=\"login\" class=\"center\"><div class=\"card login\">",
  "<div class=\"brand\"><span class=\"dot\"></span><h2>JBRouter</h2></div>",
  "<div class=\"muted\">Admin login</div>",
  "<label>Password</label>",
  "<input id=\"lp\" type=\"password\" autocomplete=\"current-password\">",
  "<button class=\"primary\" id=\"lb\" style=\"width:100%;margin-top:16px\">Log in</button>",
  "<div id=\"le\" class=\"err\"></div>",
  "</div></div>",

  "<div id=\"force\" class=\"center hide\"><div class=\"card login\">",
  "<div class=\"brand\"><span class=\"dot\" style=\"background:var(--warn);box-shadow:0 0 0 4px var(--warn-soft)\"></span><h2>Set a new password</h2></div>",
  "<div class=\"muted\">The default password must be changed before continuing.</div>",
  "<label>Current password</label>",
  "<input id=\"fc\" type=\"password\" autocomplete=\"current-password\">",
  "<label>New password</label>",
  "<input id=\"fn\" type=\"password\" autocomplete=\"new-password\">",
  "<label>Confirm new password</label>",
  "<input id=\"fx\" type=\"password\" autocomplete=\"new-password\">",
  "<button class=\"primary\" id=\"fb\" style=\"width:100%;margin-top:16px\">Set password</button>",
  "<div id=\"fe\" class=\"err\"></div>",
  "</div></div>",

  "<div id=\"app\" class=\"hide\">",
  "<div class=\"top\">",
  "<b><span class=\"dot\" style=\"width:7px;height:7px;border-radius:50%;background:var(--success);display:inline-block\"></span> JBRouter</b>",
  "<button class=\"secondary\" id=\"logout\">Log out</button>",
  "</div>",

  "<div class=\"tabs\">",
  "<div class=\"tab active\" data-s=\"roles\">Role Mapping</div>",
  "<div class=\"tab\" data-s=\"pools\">Pools</div>",
  "<div class=\"tab\" data-s=\"providers\">Providers</div>",
  "<div class=\"tab\" data-s=\"security\">Security</div>",
  "</div>",

  "<div class=\"wide\">",

  "<section id=\"roles\" class=\"sec active\">",
  "<h2>Role Mapping</h2>",
  "<div class=\"muted section-note\">The most specific matching keyword selects the pool for an incoming model name; otherwise the default pool is used.</div>",
  "<div id=\"rules\"></div>",
  "<button class=\"secondary\" id=\"addRule\">+ Add rule</button>",
  "<label>Default pool</label>",
  "<select id=\"defaultPool\"></select>",
  "<div class=\"actions\">",
  "<button class=\"primary\" id=\"saveRoles\">Save role mapping</button>",
  "</div>",
  "<div id=\"rmmsg\" class=\"ok\"></div>",
  "</section>",

  "<section id=\"pools\" class=\"sec\">",
  "<h2>Pools</h2>",
  "<div class=\"muted section-note\">Each pool is an ordered fallback list of provider + model entries. If every entry in a pool fails, its optional \\\"fall back to pool\\\" setting lets the router continue into an entirely different pool — useful when a pool's entries share one quota (e.g. several free models on the same account) and rotating within it can't help.</div>",
  "<div id=\"poolList\"></div>",
  "<button class=\"secondary\" id=\"addPool\">+ Add pool</button>",
  "</section>",

  "<section id=\"providers\" class=\"sec\">",
  "<h2>Providers</h2>",
  "<div class=\"muted section-note\">OpenAI-compatible, Gemini (native or via Cloudflare AI Gateway), or another Anthropic-compatible API.</div>",
  "<div id=\"providerList\"></div>",
  "<button class=\"secondary\" id=\"addProvider\">+ Add provider</button>",
  "</section>",

  "<section id=\"security\" class=\"sec\">",
  "<h2>Security</h2>",
  "<div class=\"grid\">",

  "<div class=\"card\">",
  "<h3>Admin password</h3>",
  "<label>Current password</label>",
  "<input id=\"sc\" type=\"password\" autocomplete=\"current-password\">",
  "<label>New password</label>",
  "<input id=\"sn\" type=\"password\" autocomplete=\"new-password\">",
  "<label>Confirm</label>",
  "<input id=\"sx\" type=\"password\" autocomplete=\"new-password\">",
  "<button class=\"primary\" id=\"sb\" style=\"margin-top:16px\">Update password</button>",
  "<div id=\"se\" class=\"err\"></div>",
  "<div id=\"sok\" class=\"ok\"></div>",
  "</div>",

  "<div class=\"card\">",
  "<h3>Router API authentication</h3>",
  "<div class=\"muted\">When enabled, /v1/messages requires:</div>",
  "<div class=\"codebox\" style=\"margin-top:10px\">Authorization: Bearer YOUR_TOKEN</div>",
  "<label class=\"check\">",
  "<input id=\"raEnabled\" type=\"checkbox\"> Enabled",
  "</label>",
  "<label>Bearer token</label>",
  "<textarea id=\"raToken\" placeholder=\"Generate or paste a token\"></textarea>",
  "<div class=\"actions\">",
  "<button class=\"secondary\" id=\"genToken\">Generate token</button>",
  "<button class=\"primary\" id=\"saveRA\">Save</button>",
  "</div>",
  "<div id=\"raStatus\" class=\"muted\"></div>",
  "<div id=\"rae\" class=\"err\"></div>",
  "<div id=\"ras\" class=\"ok\"></div>",
  "</div>",

  "</div>",
  "</section>",

  "</div>",
  "</div>",

  "<script>",
  "var S = null;",

  "async function api(path, options) {",
  "  var opts = options || {};",
  "  opts.headers = Object.assign({\"Content-Type\":\"application/json\"}, opts.headers || {});",
  "  var response = await fetch(path, opts);",
  "  var data = null;",
  "  try { data = await response.json(); } catch (_) {}",
  "  return {ok:response.ok,status:response.status,data:data};",
  "}",

  "function esc(value) {",
  "  return String(value == null ? \"\" : value).replace(/[&<>\"']/g,function(c){",
  "    if(c === \"&\") return \"&amp;\";",
  "    if(c === \"<\") return \"&lt;\";",
  "    if(c === \">\") return \"&gt;\";",
  "    if(c === '\"') return \"&quot;\";",
  "    return \"&#39;\";",
  "  });",
  "}",

  "async function boot() {",
  "  var r = await api(\"/admin/api/state\");",
  "  if(!r.ok){",
  "    document.getElementById(\"app\").classList.add(\"hide\");",
  "    document.getElementById(\"force\").classList.add(\"hide\");",
  "    document.getElementById(\"login\").classList.remove(\"hide\");",
  "    return;",
  "  }",
  "  S = r.data;",
  "  document.getElementById(\"login\").classList.add(\"hide\");",
  "  if(S.mustChangePassword){",
  "    document.getElementById(\"force\").classList.remove(\"hide\");",
  "    document.getElementById(\"app\").classList.add(\"hide\");",
  "  }else{",
  "    document.getElementById(\"force\").classList.add(\"hide\");",
  "    document.getElementById(\"app\").classList.remove(\"hide\");",
  "    render();",
  "  }",
  "}",

  "document.getElementById(\"lb\").onclick = async function(){",
  "  var r = await api(\"/admin/api/login\",{",
  "    method:\"POST\",",
  "    body:JSON.stringify({password:document.getElementById(\"lp\").value})",
  "  });",
  "  var e = document.getElementById(\"le\");",
  "  if(!r.ok){",
  "    e.textContent = r.data && r.data.error ? r.data.error : \"Login failed.\";",
  "    return;",
  "  }",
  "  e.textContent = \"\";",
  "  await boot();",
  "};",

  "document.getElementById(\"lp\").addEventListener(\"keydown\",function(e){",
  "  if(e.key === \"Enter\") document.getElementById(\"lb\").click();",
  "});",

  "document.getElementById(\"fb\").onclick = async function(){",
  "  var currentPassword = document.getElementById(\"fc\").value;",
  "  var newPassword = document.getElementById(\"fn\").value;",
  "  var confirmPassword = document.getElementById(\"fx\").value;",
  "  var e = document.getElementById(\"fe\");",
  "  e.textContent = \"\";",
  "  if(newPassword.length < 8){",
  "    e.textContent = \"New password must be at least 8 characters.\";",
  "    return;",
  "  }",
  "  if(newPassword !== confirmPassword){",
  "    e.textContent = \"Passwords do not match.\";",
  "    return;",
  "  }",
  "  var r = await api(\"/admin/api/change-password\",{",
  "    method:\"POST\",",
  "    body:JSON.stringify({currentPassword:currentPassword,newPassword:newPassword})",
  "  });",
  "  if(!r.ok){",
  "    e.textContent = r.data && r.data.error ? r.data.error : \"Could not change password.\";",
  "    return;",
  "  }",
  "  await boot();",
  "};",

  "document.getElementById(\"logout\").onclick = async function(){",
  "  await api(\"/admin/api/logout\",{method:\"POST\"});",
  "  location.reload();",
  "};",

  "document.querySelectorAll(\".tab\").forEach(function(tab){",
  "  tab.onclick = function(){",
  "    document.querySelectorAll(\".tab\").forEach(function(t){t.classList.remove(\"active\");});",
  "    document.querySelectorAll(\".sec\").forEach(function(s){s.classList.remove(\"active\");});",
  "    tab.classList.add(\"active\");",
  "    document.getElementById(tab.dataset.s).classList.add(\"active\");",
  "  };",
  "});",

  "function poolOpts(selected){",
  "  var html = \"\";",
  "  Object.values(S.pools || {}).forEach(function(p){",
  "    html += \"<option value=\\\"\" + esc(p.id) + \"\\\"\" + (p.id === selected ? \" selected\" : \"\") + \">\" + esc(p.label) + \" (\" + esc(p.id) + \")</option>\";",
  "  });",
  "  return html;",
  "}",

  "function providerOpts(selected){",
  "  var html = \"\";",
  "  Object.values(S.providers || {}).forEach(function(p){",
  "    html += \"<option value=\\\"\" + esc(p.id) + \"\\\"\" + (p.id === selected ? \" selected\" : \"\") + \">\" + esc(p.label) + \" (\" + esc(p.id) + \")</option>\";",
  "  });",
  "  return html;",
  "}",

  "function render(){",
  "  renderRoles();",
  "  renderPools();",
  "  renderProviders();",
  "  renderSecurity();",
  "}",

  "function renderRoles(){",
  "  var c = document.getElementById(\"rules\");",
  "  c.innerHTML = \"\";",
  "  var rules = S.roleMap.rules || [];",
  "  if(!rules.length){",
  "    c.innerHTML = \"<div class=\\\"empty\\\">No rules yet — every request will use the default pool below.</div>\";",
  "  }",
  "  rules.forEach(function(r,i){",
  "    var d = document.createElement(\"div\");",
  "    d.className = \"row\";",
  "    d.innerHTML = \"<input value=\\\"\" + esc(r.keyword) + \"\\\" placeholder=\\\"keyword\\\"><select>\" + poolOpts(r.poolId) + \"</select><button class=\\\"danger\\\">✕</button>\";",
  "    d.children[0].oninput = function(e){r.keyword=e.target.value;};",
  "    d.children[1].onchange = function(e){r.poolId=e.target.value;};",
  "    d.children[2].onclick = function(){S.roleMap.rules.splice(i,1);renderRoles();};",
  "    c.appendChild(d);",
  "  });",
  "  var dp = document.getElementById(\"defaultPool\");",
  "  dp.innerHTML = poolOpts(S.roleMap.defaultPoolId);",
  "  dp.onchange = function(e){S.roleMap.defaultPoolId=e.target.value;};",
  "}",

  "document.getElementById(\"addRule\").onclick = function(){",
  "  S.roleMap.rules.push({keyword:\"\",poolId:Object.keys(S.pools || {})[0] || \"\"});",
  "  renderRoles();",
  "};",

  "document.getElementById(\"saveRoles\").onclick = async function(){",
  "  var r = await api(\"/admin/api/rolemap\",{method:\"POST\",body:JSON.stringify(S.roleMap)});",
  "  var msg = document.getElementById(\"rmmsg\");",
  "  msg.textContent = r.ok ? \"Saved.\" : (r.data && r.data.error ? r.data.error : \"Save failed.\");",
  "};",

  "function renderPools(){",
  "  var c = document.getElementById(\"poolList\");",
  "  c.innerHTML = \"\";",
  "  var list = Object.values(S.pools || {});",
  "  if(!list.length){",
  "    c.innerHTML = \"<div class=\\\"empty\\\">No pools yet. Add one below.</div>\";",
  "    return;",
  "  }",
  "  list.forEach(function(p){c.appendChild(poolCard(p));});",
  "}",

  "function poolCard(p){",
  "  var d = document.createElement(\"div\");",
  "  d.className = \"item\";",
  "  d.innerHTML = \"<div class=\\\"title\\\"><div><input data-l value=\\\"\" + esc(p.label) + \"\\\"><div class=\\\"id\\\">\" + esc(p.id) + \"</div></div><button data-del class=\\\"danger\\\">Delete pool</button></div><div data-entries></div><button data-add class=\\\"secondary\\\" style=\\\"margin-top:6px\\\">+ Add fallback entry</button><hr class=\\\"sep\\\">\";",

  "  var fbWrap = document.createElement(\"div\");",
  "  var fbLabel = document.createElement(\"label\");",
  "  fbLabel.textContent = \"If every entry above fails, fall back to pool\";",
  "  var fbSelect = document.createElement(\"select\");",
  "  fbSelect.innerHTML = \"<option value=\\\"\\\">(none — fail normally)</option>\" + poolOpts(p.fallbackPoolId || \"\");",
  "  fbSelect.onchange = function(e){p.fallbackPoolId = e.target.value;};",
  "  var fbNote = document.createElement(\"div\");",
  "  fbNote.className = \"muted\";",
  "  fbNote.style.marginTop = \"6px\";",
  "  fbNote.textContent = \"Use this when a pool's entries share one rate limit (e.g. several free models on the same account) so rotation alone can't help.\";",
  "  fbWrap.appendChild(fbLabel);",
  "  fbWrap.appendChild(fbSelect);",
  "  fbWrap.appendChild(fbNote);",
  "  d.appendChild(fbWrap);",

  "  var actionsWrap = document.createElement(\"div\");",
  "  actionsWrap.className = \"actions\";",
  "  var saveBtn = document.createElement(\"button\");",
  "  saveBtn.className = \"primary\";",
  "  saveBtn.setAttribute(\"data-save\",\"\");",
  "  saveBtn.textContent = \"Save pool\";",
  "  actionsWrap.appendChild(saveBtn);",
  "  d.appendChild(actionsWrap);",

  "  var msgEl = document.createElement(\"div\");",
  "  msgEl.className = \"ok\";",
  "  msgEl.setAttribute(\"data-msg\",\"\");",
  "  d.appendChild(msgEl);",

  "  var list = d.querySelector(\"[data-entries]\");",

  "  function draw(){",
  "    list.innerHTML = \"\";",
  "    if(!(p.entries || []).length){",
  "      list.innerHTML = \"<div class=\\\"empty\\\" style=\\\"padding:14px;margin-bottom:10px\\\">No entries yet.</div>\";",
  "    }",
  "    (p.entries || []).forEach(function(e,i){",
  "      var r = document.createElement(\"div\");",
  "      r.className = \"row\";",
  "      r.innerHTML = \"<select>\" + providerOpts(e.providerId) + \"</select><input value=\\\"\" + esc(e.model) + \"\\\" placeholder=\\\"model\\\"><button class=\\\"danger\\\">✕</button>\";",
  "      r.children[0].onchange = function(x){e.providerId=x.target.value;};",
  "      r.children[1].oninput = function(x){e.model=x.target.value;};",
  "      r.children[2].onclick = function(){p.entries.splice(i,1);draw();};",
  "      list.appendChild(r);",
  "    });",
  "  }",

  "  draw();",

  "  d.querySelector(\"[data-l]\").oninput = function(e){p.label=e.target.value;};",

  "  d.querySelector(\"[data-add]\").onclick = function(){",
  "    p.entries.push({providerId:Object.keys(S.providers || {})[0] || \"\",model:\"\"});",
  "    draw();",
  "  };",

  "  saveBtn.onclick = async function(){",
  "    var r = await api(\"/admin/api/pools\",{method:\"POST\",body:JSON.stringify(p)});",
  "    msgEl.textContent = r.ok ? \"Saved.\" : (r.data && r.data.error ? r.data.error : \"Save failed.\");",
  "    if(r.ok) await refresh();",
  "  };",

  "  d.querySelector(\"[data-del]\").onclick = async function(){",
  "    if(!confirm(\"Delete pool \\\"\" + p.label + \"\\\"?\")) return;",
  "    var r = await api(\"/admin/api/pools/\" + encodeURIComponent(p.id),{method:\"DELETE\"});",
  "    if(r.ok) await refresh();",
  "  };",

  "  return d;",
  "}",

  "document.getElementById(\"addPool\").onclick = function(){",
  "  var id = \"pool-\" + Math.random().toString(36).slice(2,8);",
  "  S.pools[id] = {id:id,label:\"New Pool\",entries:[],fallbackPoolId:\"\"};",
  "  renderPools();",
  "  renderRoles();",
  "};",

  "function renderProviders(){",
  "  var c = document.getElementById(\"providerList\");",
  "  c.innerHTML = \"\";",
  "  var list = Object.values(S.providers || {});",
  "  if(!list.length){",
  "    c.innerHTML = \"<div class=\\\"empty\\\">No providers yet. Add one below.</div>\";",
  "    return;",
  "  }",
  "  list.forEach(function(p){c.appendChild(providerCard(p));});",
  "}",

  "function providerCard(p){",
  "  var d = document.createElement(\"div\");",
  "  d.className = \"item\";",

  "  var cfStatus = p.hasCfAigToken ? \"<span class=\\\"muted\\\">(currently set)</span>\" : \"<span class=\\\"muted\\\">(not set)</span>\";",
  "  var maskedKeys = p.apiKeysMasked && p.apiKeysMasked.length ? \"— \" + p.apiKeysMasked.join(\", \") : \"\";",

  "  d.innerHTML =",
  "    \"<div class=\\\"title\\\"><div><input data-label value=\\\"\" + esc(p.label) + \"\\\"><div class=\\\"id\\\">\" + esc(p.id) + \" <span class=\\\"pill\\\">\" + esc(p.kind) + \"</span></div></div><button data-del class=\\\"danger\\\">Delete provider</button></div>\" +",
  "    \"<div class=\\\"grid\\\"><div><label>Kind</label><select data-kind>\" +",
  "      \"<option value=\\\"openai\\\"\" + (p.kind === \"openai\" ? \" selected\" : \"\") + \">OpenAI-compatible</option>\" +",
  "      \"<option value=\\\"gemini\\\"\" + (p.kind === \"gemini\" ? \" selected\" : \"\") + \">Gemini</option>\" +",
  "      \"<option value=\\\"anthropic\\\"\" + (p.kind === \"anthropic\" ? \" selected\" : \"\") + \">Anthropic-compatible</option>\" +",
  "    \"</select></div><div><label>Base URL</label><input data-url value=\\\"\" + esc(p.baseUrl) + \"\\\" placeholder=\\\"https://...\\\"></div></div>\" +",
  "    \"<div class=\\\"grid\\\"><div><label>CF AI Gateway token \" + cfStatus + \"</label><input data-cf type=\\\"text\\\" placeholder=\\\"blank = keep existing\\\"></div>\" +",
  "    \"<div><label>Anthropic version</label><input data-av value=\\\"\" + esc(p.anthropicVersion || \"\") + \"\\\" placeholder=\\\"2023-06-01\\\"></div></div>\" +",
  "    \"<label>Extra headers (JSON object)</label><textarea data-h placeholder='{\\\"X-Custom-Header\\\":\\\"value\\\"}'></textarea>\" +",
  "    \"<div class=\\\"muted\\\">Custom upstream headers. Values are stored in KV.</div>\" +",
  "    \"<label>API keys (\" + String(p.apiKeyCount || 0) + \") \" + maskedKeys + \"</label>\" +",
  "    \"<textarea data-k placeholder=\\\"blank = keep existing; one key per line or comma-separated\\\"></textarea>\" +",
  "    \"<div class=\\\"actions\\\"><button data-save class=\\\"primary\\\">Save provider</button></div>\" +",
  "    \"<div data-msg class=\\\"ok\\\"></div>\";",

  "  d.querySelector(\"[data-h]\").value = JSON.stringify(p.extraHeaders || {},null,2);",
  "  d.querySelector(\"[data-label]\").oninput = function(e){p.label=e.target.value;};",
  "  d.querySelector(\"[data-kind]\").onchange = function(e){p.kind=e.target.value;};",
  "  d.querySelector(\"[data-url]\").oninput = function(e){p.baseUrl=e.target.value;};",

  "  d.querySelector(\"[data-save]\").onclick = async function(){",
  "    var headers = {};",
  "    var text = d.querySelector(\"[data-h]\").value.trim();",

  "    if(text){",
  "      try{headers=JSON.parse(text);}",
  "      catch(e){",
  "        d.querySelector(\"[data-msg]\").textContent = \"Invalid headers JSON: \" + e.message;",
  "        return;",
  "      }",

  "      if(!headers || Array.isArray(headers) || typeof headers !== \"object\"){",
  "        d.querySelector(\"[data-msg]\").textContent = \"Extra headers must be a JSON object.\";",
  "        return;",
  "      }",

  "      var clean = {};",
  "      Object.keys(headers).forEach(function(key){clean[String(key)] = String(headers[key]);});",
  "      headers = clean;",
  "    }",

  "    var r = await api(\"/admin/api/providers\",{",
  "      method:\"POST\",",
  "      body:JSON.stringify({",
  "        id:p.id,",
  "        label:p.label,",
  "        kind:p.kind,",
  "        baseUrl:p.baseUrl,",
  "        cfAigToken:d.querySelector(\"[data-cf]\").value,",
  "        anthropicVersion:d.querySelector(\"[data-av]\").value,",
  "        extraHeaders:headers,",
  "        apiKeysRaw:d.querySelector(\"[data-k]\").value",
  "      })",
  "    });",

  "    d.querySelector(\"[data-msg]\").textContent = r.ok ? \"Saved.\" : (r.data && r.data.error ? r.data.error : \"Save failed.\");",
  "    if(r.ok) await refresh();",
  "  };",

  "  d.querySelector(\"[data-del]\").onclick = async function(){",
  "    if(!confirm(\"Delete provider \\\"\" + p.label + \"\\\"? Pools referencing it will break until you fix them.\")) return;",
  "    var r = await api(\"/admin/api/providers/\" + encodeURIComponent(p.id),{method:\"DELETE\"});",
  "    if(r.ok) await refresh();",
  "  };",

  "  return d;",
  "}",

  "document.getElementById(\"addProvider\").onclick = function(){",
  "  var id = \"provider-\" + Math.random().toString(36).slice(2,8);",
  "  S.providers[id] = {id:id,label:\"New Provider\",kind:\"openai\",baseUrl:\"\",hasCfAigToken:false,anthropicVersion:\"\",extraHeaders:{},apiKeyCount:0,apiKeysMasked:[]};",
  "  renderProviders();",
  "  renderPools();",
  "};",

  "/* PASSWORD CHANGE */",

  "document.getElementById(\"sb\").onclick = async function(){",
  "  var currentPassword = document.getElementById(\"sc\").value;",
  "  var newPassword = document.getElementById(\"sn\").value;",
  "  var confirmPassword = document.getElementById(\"sx\").value;",
  "  var err = document.getElementById(\"se\");",
  "  var ok = document.getElementById(\"sok\");",

  "  err.textContent = \"\";",
  "  ok.textContent = \"\";",

  "  if(newPassword.length < 8){",
  "    err.textContent = \"New password must be at least 8 characters.\";",
  "    return;",
  "  }",

  "  if(newPassword !== confirmPassword){",
  "    err.textContent = \"Passwords do not match.\";",
  "    return;",
  "  }",

  "  var r = await api(\"/admin/api/change-password\",{",
  "    method:\"POST\",",
  "    body:JSON.stringify({currentPassword:currentPassword,newPassword:newPassword})",
  "  });",

  "  if(!r.ok){",
  "    err.textContent = r.data && r.data.error ? r.data.error : \"Failed.\";",
  "    return;",
  "  }",

  "  document.getElementById(\"sc\").value = \"\";",
  "  document.getElementById(\"sn\").value = \"\";",
  "  document.getElementById(\"sx\").value = \"\";",

  "  ok.textContent = \"Password updated. Other admin sessions are invalidated.\";",
  "};",

  "/* ROUTER AUTH */",

  "function renderSecurity(){",
  "  document.getElementById(\"raEnabled\").checked = !!(S.routerAuth && S.routerAuth.enabled);",
  "  document.getElementById(\"raToken\").value = S.routerAuth && S.routerAuth.token ? S.routerAuth.token : \"\";",
  "  document.getElementById(\"raStatus\").textContent = (S.routerAuth && S.routerAuth.enabled) ? \"Enabled — bearer token required.\" : \"Disabled — /v1/messages is open.\";",
  "}",

  "document.getElementById(\"genToken\").onclick = function(){",
  "  var bytes = crypto.getRandomValues(new Uint8Array(32));",
  "  var hex = \"\";",
  "  for(var i=0;i<bytes.length;i++){",
  "    var h = bytes[i].toString(16);",
  "    hex += h.length === 1 ? \"0\" + h : h;",
  "  }",
  "  document.getElementById(\"raToken\").value = hex;",
  "};",

  "document.getElementById(\"saveRA\").onclick = async function(){",
  "  var enabled = document.getElementById(\"raEnabled\").checked;",
  "  var token = document.getElementById(\"raToken\").value.trim();",
  "  var err = document.getElementById(\"rae\");",
  "  var ok = document.getElementById(\"ras\");",

  "  err.textContent = \"\";",
  "  ok.textContent = \"\";",

  "  var r = await api(\"/admin/api/router-auth\",{",
  "    method:\"POST\",",
  "    body:JSON.stringify({enabled:enabled,token:token})",
  "  });",

  "  if(!r.ok){",
  "    err.textContent = r.data && r.data.error ? r.data.error : \"Failed.\";",
  "    return;",
  "  }",

  "  S.routerAuth = {enabled:enabled,token:token};",
  "  renderSecurity();",

  "  ok.textContent = enabled ? \"Router authentication enabled.\" : \"Router authentication disabled.\";",
  "};",

  "/* REFRESH */",

  "async function refresh(){",
  "  var r = await api(\"/admin/api/state\");",
  "  if(r.ok){",
  "    S = r.data;",
  "    render();",
  "  }",
  "}",

  "boot();",
  "</script>",
  "</body>",
  "</html>"
].join("\n");

/* ============================================================
   WORKER FETCH
   ============================================================ */

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      /* HEALTH */
      if (
        request.method === "GET" &&
        url.pathname === "/health"
      ) {
        return new Response("OK", {
          status: 200,
          headers: {
            "content-type":
              "text/plain; charset=utf-8"
          }
        });
      }

      /* ADMIN */
      if (
        url.pathname.startsWith("/admin")
      ) {
        return await admin(
          request,
          env,
          url
        );
      }

      /* ROUTER */
      if (
        request.method !== "POST" ||
        url.pathname !== "/v1/messages"
      ) {
        return new Response(
          "Not Found",
          {
            status: 404,
            headers: {
              "content-type":
                "text/plain; charset=utf-8"
            }
          }
        );
      }

      return await router(
        request,
        env
      );

    } catch (e) {
      return aerr(
        e?.message ||
          "Internal Worker error.",
        "internal_error",
        500
      );
    }
  }
};