// Офлайн-оболочка: файлы приложения берём из сети, а без сети - из кэша.
// Запросы к серверу здесь не кэшируются (их зашифрованный кэш ведёт само приложение).

const CACHE = 'keybox-v6';
const FILES = [
  './', 'index.html', 'manifest.webmanifest', 'css/app.css',
  'js/app.js', 'js/config.js', 'js/crypto.js', 'js/storage.js', 'js/tools.js', 'js/ui.js', 'js/vault.js',
  'vendor/argon2.umd.min.js', 'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png',
];

// Мимо HTTP-кэша браузера: GitHub Pages разрешает держать файлы 10 минут, и после обновления
// старая страница (со старым CSP) могла бы смешаться с новым кодом
const fresh = req => fetch(req.url, { cache: 'no-cache', credentials: 'same-origin' });

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE)
    .then(c => c.addAll(FILES.map(f => new Request(f, { cache: 'reload' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys()
    .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  // Адреса с параметрами не кэшируем
  if (url.search) {
    e.respondWith(fresh(e.request).catch(() => caches.match('index.html')));
    return;
  }
  e.respondWith(
    fresh(e.request)
      .then(r => {
        if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
        return r;
      })
      .catch(() => caches.match(e.request).then(r => r || caches.match('index.html'))));
});
