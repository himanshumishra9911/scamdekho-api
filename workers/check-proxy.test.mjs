import test from "node:test";
import assert from "node:assert/strict";
import worker from "./check-proxy.js";

const URL = "https://scamdekho.in/check/test.example";
const report = (body = "completed") => new Response(body, {
  headers: { "X-ScamDekho-Edge-Cacheable": "yes", "Cache-Control": "public, max-age=300" },
});
const shell = () => new Response("Checking", {
  headers: { "X-ScamDekho-Edge-Cacheable": "no", "X-Robots-Tag": "noindex, follow", "Cache-Control": "no-store" },
});
function harness(origin = () => report()) {
  const entries = new Map(), pending = [], calls = [];
  globalThis.caches = { default: {
    async match(key) { return entries.get(key.url)?.clone(); },
    async put(key, response) { entries.set(key.url, response.clone()); },
    async delete(key) { return entries.delete(key.url); },
  } };
  globalThis.fetch = async (request, options) => {
    calls.push({ request, options });
    return origin(request, options);
  };
  return { entries, calls,
    async run(url = URL, options) {
      const response = await worker.fetch(new Request(url, options), {}, {
        waitUntil(promise) { pending.push(promise); },
      });
      await Promise.all(pending.splice(0));
      return response;
    },
    age(seconds) {
      for (const [key, response] of entries) {
        const headers = new Headers(response.headers);
        headers.set("X-ScamDekho-Cache-Stored-At", String(Date.now() - seconds * 1000));
        entries.set(key, new Response(response.clone().body, { headers }));
      }
    },
  };
}

test("completed reports MISS then HIT; no forced origin caching", async () => {
  const h = harness();
  assert.equal((await h.run()).headers.get("X-ScamDekho-Edge-Cache"), "MISS");
  const hit = await h.run();
  assert.equal(hit.headers.get("X-ScamDekho-Edge-Cache"), "HIT");
  assert.equal(await hit.text(), "completed");
  assert.equal(h.calls.length, 1);
  assert.deepEqual(h.calls[0].options, { cache: "no-store" });
  assert.equal(new globalThis.URL(h.calls[0].request.url).search, "");
});
test("noindex shells never cached; completed scan immediately replaces them", async () => {
  let completed = false;
  const h = harness(() => completed ? report() : shell());
  for (let i = 0; i < 2; i++) {
    const response = await h.run();
    assert.equal(response.headers.get("X-ScamDekho-Edge-Cache"), "BYPASS");
    assert.match(response.headers.get("Cache-Control"), /no-store/);
    assert.match(response.headers.get("X-Robots-Tag"), /noindex/);
    assert.equal(h.entries.size, 0);
  }
  completed = true;
  assert.equal(await (await h.run()).text(), "completed");
});
test("old cache namespace and unsafe new entries cannot poison reports", async () => {
  const h = harness();
  h.entries.set(URL, shell());
  await h.run();
  const newKey = [...h.entries.keys()].find(key => key !== URL);
  h.entries.set(newKey, shell());
  assert.equal(await (await h.run()).text(), "completed");
  assert.equal(h.calls.length, 2);
});
test("HEAD caches GET body, not an empty response", async () => {
  const h = harness();
  assert.equal(await (await h.run(URL, { method: "HEAD" })).text(), "");
  assert.equal(await (await h.run()).text(), "completed");
  assert.equal(h.calls[0].request.method, "GET");
});
test("stale completed report survives 503 and network failure, but expires", async () => {
  let mode = "ok";
  const h = harness(() => {
    if (mode === "throw") throw new Error("offline");
    return mode === "ok" ? report() : new Response("offline", { status: 503 });
  });
  await h.run(); h.age(1000); mode = "503";
  assert.equal((await h.run()).headers.get("X-ScamDekho-Edge-Cache"), "STALE");
  mode = "throw";
  const stale = await h.run();
  assert.equal(await stale.text(), "completed");
  assert.match(stale.headers.get("Cache-Control"), /no-store/);
  h.age(7 * 86400 + 1);
  assert.equal((await h.run()).status, 503);
});
test("stale report refreshes; shell or 404 invalidates old content", async () => {
  let origin = report;
  const h = harness(() => origin());
  await h.run(); h.age(1000);
  origin = () => report("updated");
  const updated = await h.run();
  assert.equal(updated.headers.get("X-ScamDekho-Edge-Cache"), "REVALIDATED");
  assert.equal(await updated.text(), "updated");
  h.age(1000); origin = shell;
  assert.equal(await (await h.run()).text(), "Checking");
  assert.equal(h.entries.size, 0);
  origin = report; await h.run(); h.age(1000);
  origin = () => new Response("gone", { status: 404 });
  assert.equal((await h.run()).status, 404);
  assert.equal(h.entries.size, 0);
});
test("private, no-store, noindex, or cookie responses cannot enter shared cache", async () => {
  for (const [name, value] of [["Cache-Control", "no-store"], ["CDN-Cache-Control", "private"],
    ["X-Robots-Tag", "noindex"], ["Set-Cookie", "session=private"]]) {
    const h = harness(() => { const r = report(); r.headers.set(name, value); return r; });
    assert.equal((await h.run()).headers.get("X-ScamDekho-Edge-Cache"), "BYPASS");
    assert.equal(h.entries.size, 0);
  }
});
test("canonical query redirect and sitemap caching work", async () => {
  const h = harness(() => new Response("<urlset/>", { headers: { "Content-Type": "application/xml" } }));
  const redirect = await h.run(URL + "?scanned=1");
  assert.equal(redirect.status, 301); assert.equal(redirect.headers.get("Location"), URL);
  const sitemap = "https://scamdekho.in/sitemap-checks.xml";
  assert.equal((await h.run(sitemap)).headers.get("X-ScamDekho-Edge-Cache"), "MISS");
  assert.equal((await h.run(sitemap)).headers.get("X-ScamDekho-Edge-Cache"), "HIT");
});
test("client no-cache refreshes; conditionals and cookies removed from full GET", async () => {
  const h = harness(); await h.run();
  await h.run(URL, { headers: { "Cache-Control": "no-cache", "If-None-Match": "old", "Cookie": "x=1", Range: "bytes=0-5" } });
  assert.equal(h.calls.length, 2);
  for (const name of ["if-none-match", "cookie", "range"]) assert.equal(h.calls[1].request.headers.has(name), false);
});
