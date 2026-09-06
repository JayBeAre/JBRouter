import { admin } from './admin/router.js';
import { debugRouter } from './debug.js';
import { router } from './router.js';
import { aerr } from './config.js';

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/health") {
        return new Response("OK", { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
      }
      if (url.pathname.startsWith("/admin")) {
        return await admin(request, env, url);
      }
      if (url.pathname === "/debug" || url.pathname.startsWith("/debug/")) {
        return await debugRouter(request, env, url);
      }
      if (request.method !== "POST" || url.pathname !== "/v1/messages") {
        return new Response("Not Found", { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
      }
      return await router(request, env);
    } catch (e) {
      return aerr(e?.message || "Internal Worker error.", "internal_error", 500);
    }
  }
};
