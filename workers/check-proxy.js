const ORIGIN = "https://scamdekho-api.onrender.com";
const CACHE_VERSION = "completed-reports-v2";
const FRESH_TTL = 15 * 60;
const RETENTION_TTL = 7 * 24 * 60 * 60;
const STORED_AT = "X-ScamDekho-Cache-Stored-At";

function isPublicReport(pathname) {
  return /^\/check\/[^/]+\/?$/.test(pathname);
}

function isPublicSitemap(pathname) {
  return pathname === "/sitemap" || pathname.startsWith("/sitemap/") ||
    pathname === "/sitemap-checks.xml" || pathname === "/sitemap-index.xml" ||
    /^\/sitemap-checks-\d+\.xml$/.test(pathname);
}

function canCache(response, report) {
  const controls = ["cache-control", "cdn-cache-control", "cloudflare-cdn-cache-control"]
    .map(name => response.headers.get(name) || "").join(",");
  return response.status === 200 && !response.headers.has("set-cookie") &&
    !/\b(no-store|private|no-cache)\b/i.test(controls) &&
    !/\bnoindex\b/i.test(response.headers.get("x-robots-tag") || "") &&
    (!report || response.headers.get("X-ScamDekho-Edge-Cacheable") === "yes");
}

function clientResponse(response, marker, headOnly, age = 0, cacheable = false) {
  const headers = new Headers(response.headers);
  headers.delete(STORED_AT);
  // Only the Worker owns shared caching; another layer must not re-cache a
  // shell, stale fallback, or outage response under the public URL.
  headers.set("CDN-Cache-Control", "no-store");
  headers.set("Cloudflare-CDN-Cache-Control", "no-store");
  headers.set("Cache-Control", cacheable && marker !== "STALE" ?
    "public, max-age=60, must-revalidate" : "no-store, max-age=0");
  headers.set("X-ScamDekho-Edge-Cache", marker);
  headers.set("X-ScamDekho-Worker-Version", CACHE_VERSION);
  if (cacheable) headers.set("Age", String(Math.max(0, Math.floor(age))));
  else headers.delete("Age");
  return new Response(headOnly ? null : response.body, {
    status: response.status, statusText: response.statusText, headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const incoming = new URL(request.url);
    const report = isPublicReport(incoming.pathname);
    const publicPath = report || isPublicSitemap(incoming.pathname);
    const method = request.method.toUpperCase();
    if (report && incoming.search && (method === "GET" || method === "HEAD")) {
      return Response.redirect(incoming.origin + incoming.pathname, 301);
    }
    const originUrl = new URL(incoming.pathname + incoming.search, ORIGIN);
    if (!publicPath || !["GET", "HEAD"].includes(method) ||
        request.headers.has("authorization")) {
      return fetch(new Request(originUrl, request), { cache: "no-store" });
    }

    const headOnly = method === "HEAD";
    const cache = caches.default;
    // Bypass poisoned entries from the September Worker. This internal
    // cache-key parameter is never sent to the origin or shown to visitors.
    const keyUrl = new URL(incoming);
    keyUrl.searchParams.set("__sd_cache_version", CACHE_VERSION);
    const cacheKey = new Request(keyUrl, { method: "GET" });
    let cached;
    try { cached = await cache.match(cacheKey); } catch { /* cache is optional */ }
    const storedAt = Number(cached?.headers.get(STORED_AT));
    const age = storedAt > 0 ? (Date.now() - storedAt) / 1000 : Infinity;
    if (cached && (!canCache(cached, report) || age < 0 || age >= RETENTION_TTL)) {
      cached = undefined;
    }
    const forceRefresh = /\b(no-cache|no-store|max-age=0)\b/i.test(
      request.headers.get("cache-control") || "",
    );
    if (cached && age < FRESH_TTL && !forceRefresh) {
      return clientResponse(cached, "HIT", headOnly, age, true);
    }

    const headers = new Headers(request.headers);
    for (const name of ["cookie", "authorization", "if-none-match", "if-modified-since", "range", "if-range"]) {
      headers.delete(name);
    }
    const controller = new AbortController();
    // A cold report may refresh its stored article on the existing backend.
    // Allow that normal work; use a short deadline only when a safe fallback exists.
    const timeout = setTimeout(() => controller.abort(), cached ? 10000 : 45000);
    try {
      // Forced subrequest caching overrides the origin's no-store before our
      // completed-report check. Disable it, and use only the explicit Cache API.
      const origin = await fetch(new Request(originUrl, {
        method: "GET", headers, redirect: "follow", signal: controller.signal,
      }), { cache: "no-store" });
      if (origin.status >= 500 && cached) {
        return clientResponse(cached, "STALE", headOnly, age, true);
      }
      if (!canCache(origin, report)) {
        // Respect genuine removals/noindex changes instead of hiding them
        // behind a stale report. Outages never replace completed cache data.
        if (origin.status < 500) {
          ctx.waitUntil(cache.delete(cacheKey).catch(() => false));
        }
        return clientResponse(origin, "BYPASS", headOnly);
      }

      const cacheHeaders = new Headers(origin.headers);
      cacheHeaders.delete("CDN-Cache-Control");
      cacheHeaders.delete("Cloudflare-CDN-Cache-Control");
      cacheHeaders.delete("Age");
      cacheHeaders.set("Cache-Control", "public, max-age=" + RETENTION_TTL);
      cacheHeaders.set(STORED_AT, String(Date.now()));
      const stored = new Response(origin.clone().body, { status: 200, headers: cacheHeaders });
      ctx.waitUntil(cache.put(cacheKey, stored).catch(() => {}));
      return clientResponse(origin, cached ? "REVALIDATED" : "MISS", headOnly, 0, true);
    } catch {
      // Cache API does not implement stale-if-error. Explicitly fall back to a
      // previously completed report retained for at most seven days.
      if (cached) return clientResponse(cached, "STALE", headOnly, age, true);
      return clientResponse(new Response("Temporary origin error", {
        status: 503, headers: { "Retry-After": "60" },
      }), "ORIGIN_ERROR", headOnly);
    } finally {
      clearTimeout(timeout);
    }
  },
};
