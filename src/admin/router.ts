import { j, aerr, K, COOKIE } from '../config.js';
import { validSession, login, changePassword } from '../auth.js';
import { providers, pools, rolemap, routerAuth, redacted, saveProvider, deleteProvider, savePool, deletePool, saveRoleMap, saveRouterAuth } from '../providers.js';
import { debugConfig, saveDebugConfig } from '../debug.js';
import { clearCookie } from '../auth.js';

export async function admin(request, env, url) {
  if (url.pathname === "/admin" && request.method === "GET") {
    return env.ASSETS.fetch(new Request(new URL("/admin/index.html", request.url)));
  }
  if (url.pathname === "/admin/api/login" && request.method === "POST") return login(request, env);
  const s = await validSession(request, env);
  if (!s) return j({ ok: false, error: "Not authenticated." }, 401);
  if (url.pathname === "/admin/api/logout" && request.method === "POST") {
    await env.CONFIG_KV.delete(K.session + s);
    return j({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (url.pathname === "/admin/api/change-password" && request.method === "POST") return changePassword(request, env);
  if (url.pathname === "/admin/api/state" && request.method === "GET") {
    const [ps, pl, rm, ra, dbg] = await Promise.all([providers(env), pools(env), rolemap(env), routerAuth(env), debugConfig(env)]);
    return j({ mustChangePassword: false, providers: redacted(ps), pools: pl, roleMap: rm, routerAuth: ra, debug: dbg });
  }
  if (url.pathname === "/admin/api/providers" && request.method === "POST") return saveProvider(request, env);
  if (url.pathname.startsWith("/admin/api/providers/") && request.method === "DELETE") return deleteProvider(env, decodeURIComponent(url.pathname.split("/").pop()));
  if (url.pathname === "/admin/api/pools" && request.method === "POST") return savePool(request, env);
  if (url.pathname.startsWith("/admin/api/pools/") && request.method === "DELETE") return deletePool(env, decodeURIComponent(url.pathname.split("/").pop()));
  if (url.pathname === "/admin/api/rolemap" && request.method === "POST") return saveRoleMap(request, env);
  if (url.pathname === "/admin/api/router-auth" && request.method === "POST") return saveRouterAuth(request, env);
  if (url.pathname === "/admin/api/debug" && request.method === "POST") return saveDebugConfig(request, env);
  return new Response("Not Found", { status: 404 });
}
