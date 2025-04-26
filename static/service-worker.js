const CACHE_NAME = "guestbook-cache-v1";
const urlsToCache = [
    "/",
    "/static/manifest.json",
    "/static/service-worker.js",
    "/static/back_image.png",
    "/static/icons/icon-192x192.png",
    "/static/icons/icon-512x512.png",
    // 可以继续加 css、js 资源
];

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/service-worker.js')
        .then(reg => {
            console.log('Service Worker 注册成功');
        })
        .catch(err => {
            console.error('Service Worker 注册失败', err);
        });
}

// 安装时缓存
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

// 拦截请求，使用缓存
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});

// 更新时清除旧缓存
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
