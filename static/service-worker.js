const CACHE_NAME = "guestbook-cache-v1";
const urlsToCache = [
    "/",
    "/static/manifest.json",
    "/static/service-worker.js",
    "/static/back_image.png",
    "/static/icons/icon-192x192.png",
    "/static/icons/icon-512x512.png",
    // ���Լ����� css��js ��Դ
];

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/service-worker.js')
        .then(reg => {
            console.log('Service Worker ע��ɹ�');
        })
        .catch(err => {
            console.error('Service Worker ע��ʧ��', err);
        });
}

// ��װʱ����
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open('v1').then((cache) => {
            return cache.addAll([
                '/',
                '/static/icons/icon-192x192.png',
                '/static/icons/icon-512x512.png',
                '/static/manifest.json'
            ]);
        })
    );
});

// ��������ʹ�û���
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});

// ����ʱ����ɻ���
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.filter(name => name !== CACHE_NAME)
                    .map(name => caches.delete(name))
            );
        })
    );
});
