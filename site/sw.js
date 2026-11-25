// Biotech Home — protected folder viewer.
// Pages under <site>/_b/<itemId>/<token>/<path> do not exist on the static host. This worker answers them by
// asking the content-access function for each file (it checks login + course access every time), so a folder
// of linked HTML pages, images, CSS and JS can be shown without ever being public.
const FN = 'https://sxwqmghmpineouxhjwdw.supabase.co/functions/v1/content-access';
const KEY = 'sb_publishable_7I-iPhzPnTEW2y2GtEA3oQ_xPcbNjuR';
const MIME = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', json: 'application/json; charset=utf-8', txt: 'text/plain; charset=utf-8',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', svg: 'image/svg+xml',
  ico: 'image/x-icon', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf', pdf: 'application/pdf'
};
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'purge') {
    e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('bh-b-')).map(k => caches.delete(k)))));
  }
});
self.addEventListener('fetch', e => {
  const pre = new URL('_b/', self.registration.scope);
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== pre.origin || !u.pathname.startsWith(pre.pathname)) return;
  e.respondWith(serve(u, pre.pathname));
});
const txt = (s, t) => new Response(t, { status: s, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
async function serve(u, prePath) {
  const rest = u.pathname.slice(prePath.length);
  const m = rest.match(/^([0-9a-f-]{36})\/([A-Za-z0-9._-]{1,4096})\/(.*)$/i);
  if (!m) return txt(404, 'Not found');
  const id = m[1], tok = m[2];
  let path;
  try { path = decodeURIComponent(m[3]); } catch (_) { return txt(400, 'Bad path'); }
  if (!path || path.endsWith('/')) path += 'index.html';
  const key = u.origin + u.pathname;
  const cache = await caches.open('bh-b-' + id);
  const hit = await cache.match(key);
  if (hit) return hit;
  const h = { 'Content-Type': 'application/json', apikey: KEY };
  if (tok !== 'anon') h.Authorization = 'Bearer ' + tok;
  let r;
  try { r = await fetch(FN, { method: 'POST', headers: h, body: JSON.stringify({ item_id: id, path }) }); }
  catch (_) { return txt(503, 'Network problem'); }
  if (!r.ok) return txt(r.status === 401 || r.status === 403 ? r.status : 404, r.status === 403 ? 'No access' : r.status === 401 ? 'Login required' : 'Not found');
  const ext = (path.split('.').pop() || '').toLowerCase();
  const body = await r.arrayBuffer();
  const res = new Response(body, { status: 200, headers: { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
  try { await cache.put(key, res.clone()); } catch (_) {}
  return res;
}
