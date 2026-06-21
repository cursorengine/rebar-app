/* CommandDeck service worker — installable, offline-tolerant app shell.
 * Strategy:
 *   - Supabase API / storage / auth: ALWAYS network, never cached (live data).
 *   - App shell (HTML/icons/manifest): network-first, fall back to cache offline.
 *   - Other GET requests (fonts, etc.): stale-while-revalidate.
 * Bump CACHE when shipping a new build to invalidate old assets.
 */
var CACHE = "commanddeck-v1";
var SHELL = [
  "./index.html",
  "./accept.html",
  "./track.html",
  "./driver.html",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png"
];

self.addEventListener("install", function(e){
  e.waitUntil(
    caches.open(CACHE).then(function(c){
      // Best-effort precache; never fail the install if one asset is missing.
      return Promise.allSettled(SHELL.map(function(u){ return c.add(u); }));
    }).then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.filter(function(k){ return k !== CACHE; })
                             .map(function(k){ return caches.delete(k); }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function(e){
  var req = e.request;
  if(req.method !== "GET"){ return; }
  var url = new URL(req.url);

  // Never intercept live backend traffic — let it hit the network directly.
  if(/supabase\.(co|in)$/.test(url.hostname) || url.pathname.indexOf("/rest/") !== -1 ||
     url.pathname.indexOf("/auth/") !== -1 || url.pathname.indexOf("/functions/") !== -1 ||
     url.pathname.indexOf("/storage/") !== -1){
    return;
  }

  // Navigations + same-origin shell: network-first, cache fallback.
  if(req.mode === "navigate" || url.origin === self.location.origin){
    e.respondWith(
      fetch(req).then(function(res){
        var copy = res.clone();
        caches.open(CACHE).then(function(c){ c.put(req, copy); });
        return res;
      }).catch(function(){
        return caches.match(req).then(function(hit){
          return hit || caches.match("./index.html");
        });
      })
    );
    return;
  }

  // Cross-origin static (fonts/CDN): stale-while-revalidate.
  e.respondWith(
    caches.match(req).then(function(hit){
      var net = fetch(req).then(function(res){
        var copy = res.clone();
        caches.open(CACHE).then(function(c){ c.put(req, copy); });
        return res;
      }).catch(function(){ return hit; });
      return hit || net;
    })
  );
});
