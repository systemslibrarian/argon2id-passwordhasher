// -----------------------------------------------------------------------------
// Cross-Origin-Isolation service worker.
//
// Some hosts (GitHub Pages, vanilla static-file servers) can't set the
// `Cross-Origin-Opener-Policy: same-origin` and
// `Cross-Origin-Embedder-Policy: require-corp` headers that a browser requires
// before it will expose SharedArrayBuffer to the page. Blazor's multi-threaded
// WebAssembly runtime needs SharedArrayBuffer to do real work on worker threads.
//
// This service worker is a small, well-known workaround: it installs itself
// from the page on first load, then intercepts every fetch and re-emits the
// response with the two policy headers added. Once isolation is established
// the page reloads once and stays isolated for the rest of the session.
//
// The worker only mutates *response headers*. It never inspects or modifies
// request bodies or response bodies, and it never makes network requests of
// its own beyond passing through the page's existing fetches.
// -----------------------------------------------------------------------------

if (typeof window === 'undefined') {
    // ----- Running inside the service worker --------------------------------
    self.addEventListener('install', () => self.skipWaiting());
    self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

    self.addEventListener('fetch', (event) => {
        // Cached requests outside same-origin scope are passed through untouched.
        if (
            event.request.cache === 'only-if-cached'
            && event.request.mode !== 'same-origin'
        ) {
            return;
        }

        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    // Don't try to wrap opaque responses (e.g. cross-origin
                    // resources without CORS). The browser would refuse them
                    // under COEP anyway; passing through preserves errors as-is.
                    if (response.status === 0) {
                        return response;
                    }

                    const headers = new Headers(response.headers);
                    headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
                    headers.set('Cross-Origin-Opener-Policy', 'same-origin');

                    return new Response(response.body, {
                        status: response.status,
                        statusText: response.statusText,
                        headers,
                    });
                })
                .catch((err) => {
                    // Network errors surface to the page as a failed fetch.
                    console.error('[coi-sw] fetch failed:', err);
                    throw err;
                }),
        );
    });
} else {
    // ----- Running in the page ----------------------------------------------
    (() => {
        if (window.crossOriginIsolated) {
            // Headers were set server-side; nothing to do.
            return;
        }
        if (!('serviceWorker' in navigator)) {
            console.warn(
                '[coi-sw] service workers not supported; '
                + 'WebAssembly will run single-threaded.',
            );
            return;
        }

        const script = window.document.currentScript;
        if (!script) {
            return;
        }

        navigator.serviceWorker.register(script.src).then(
            (registration) => {
                if (registration.active && !navigator.serviceWorker.controller) {
                    // The worker is installed but isn't yet controlling this
                    // page (first load). Reload so the next request goes
                    // through the worker and isolation kicks in.
                    window.location.reload();
                }
                registration.addEventListener('updatefound', () => {
                    window.location.reload();
                });
            },
            (err) => {
                console.error('[coi-sw] registration failed:', err);
            },
        );
    })();
}
