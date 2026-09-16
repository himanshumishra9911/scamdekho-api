const ORIGIN = "https://scamdekho-api.onrender.com";
const REPORT_EDGE_TTL = 7 * 24 * 60 * 60;
const SITEMAP_EDGE_TTL = 60 * 60;
const STALE_TTL = 30 * 24 * 60 * 60;

function isPublicReport(pathname) {
  return /^\/check\/[^/]+\/?$/.test(pathname);
}

function isPublicSitemap(pathname) {
  return pathname === "/sitemap" || pathname.startsWith("/sitemap/") ||
    pathname === "/sitemap-checks.xml" ||
    pathname === "/sitemap-index.xml" ||
    /^\/sitemap-checks-\d+\.xml$/.test(pathname);
}

function edgeTtl(pathname) {
  if (isPublicReport(pathname)) return REPORT_EDGE_TTL;
  if (isPublicSitemap(pathname)) return SITEMAP_EDGE_TTL;
  return 0;
}

function responseWithCacheHeaders(response, ttl, marker, headOnly = false) {
  const headers = new Headers(response.headers);
  headers.delete("set-cookie");
  headers.set(
    "Cache-Control",
    `public, max-age=300, s-maxage=${ttl}, stale-while-revalidate=${STALE_TTL}, stale-if-error=${STALE_TTL}`,
  );
  headers.set(
    "CDN-Cache-Control",
    `public, max-age=${ttl}, stale-while-revalidate=${STALE_TTL}, stale-if-error=${STALE_TTL}`,
  );
  headers.set("X-ScamDekho-Edge-Cache", marker);
  return new Response(headOnly ? null : response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const incoming = new URL(request.url);
    const method = request.method.toUpperCase();
    const ttl = edgeTtl(incoming.pathname);

    // The old scanning flow appended ?scanned=1. One permanent URL prevents
    // duplicate/noindex history from consuming crawl budget.
    if (isPublicReport(incoming.pathname) && incoming.search) {
      return Response.redirect(`${incoming.origin}${incoming.pathname}`, 301);
    }

    const originUrl = new URL(incoming.pathname + incoming.search, ORIGIN);
    if ((method !== "GET" && method !== "HEAD") || !ttl) {
      return fetch(new Request(originUrl, request));
    }

    const cache = caches.default;
    const cacheKey = new Request(incoming.toString(), { method: "GET" });
    const cached = await cache.match(cacheKey);
    if (cached) {
      const hit = responseWithCacheHeaders(cached, ttl, "HIT", method === "HEAD");
      hit.headers.set("Age", cached.headers.get("Age") || "0");
      return hit;
    }

    // Render returns 405 for HEAD on these FastAPI routes. Fetch GET once,
    // cache it, and return headers only to the HEAD caller.
    const originHeaders = new Headers(request.headers);
    originHeaders.delete("cookie");
    originHeaders.delete("authorization");
    const originRequest = new Request(originUrl, {
      method: "GET",
      headers: originHeaders,
      redirect: "follow",
    });

    try {
      const originResponse = await fetch(originRequest, {
        cf: {
          cacheEverything: true,
          cacheTtlByStatus: {
            "200-299": ttl,
            "300-399": 300,
            "400-499": 30,
            "500-599": 0,
          },
        },
      });

      if (!originResponse.ok) {
        return new Response(method === "HEAD" ? null : originResponse.body, {
          status: originResponse.status,
          statusText: originResponse.statusText,
          headers: originResponse.headers,
        });
      }

      const cacheResponse = responseWithCacheHeaders(
        originResponse.clone(),
        ttl,
        "MISS",
      );
      ctx.waitUntil(cache.put(cacheKey, cacheResponse.clone()));
      return responseWithCacheHeaders(
        originResponse,
        ttl,
        "MISS",
        method === "HEAD",
      );
    } catch (error) {
      // Never cache an outage page. Googlebot receives a retryable response
      // instead of a misleading 200 with thin/error content.
      return new Response(method === "HEAD" ? null : "Temporary origin error", {
        status: 503,
        headers: {
          "Cache-Control": "no-store",
          "Retry-After": "60",
          "X-ScamDekho-Edge-Cache": "ORIGIN_ERROR",
        },
      });
    }
  },
};
