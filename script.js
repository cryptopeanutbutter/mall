const body = document.body;
const portalDot = document.querySelector('.glyph-dot');
const portalOverlay = document.querySelector('.portal-overlay');
const closePortalBtn = document.querySelector('.close-portal');
let portalTimer;

function openPortal() {
    if (body.classList.contains('portal-open') || body.classList.contains('portal-activating')) {
        return;
    }

    body.classList.add('portal-activating');

    portalTimer = window.setTimeout(() => {
        body.classList.add('portal-open');
        portalOverlay?.setAttribute('aria-hidden', 'false');
        body.classList.remove('portal-activating');
    }, 1400);
}

function closePortal() {
    window.clearTimeout(portalTimer);
    body.classList.remove('portal-open', 'portal-activating');
    portalOverlay?.setAttribute('aria-hidden', 'true');
}

portalDot?.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    openPortal();
});

closePortalBtn?.addEventListener('click', (event) => {
    event.preventDefault();
    closePortal();
});

portalOverlay?.addEventListener('click', (event) => {
    if (event.target === portalOverlay) {
        closePortal();
    }
});

document.addEventListener('keyup', (event) => {
    if (event.key === 'Escape') {
        closePortal();
    }
});

window.addEventListener('pageshow', () => {
    portalOverlay?.setAttribute('aria-hidden', 'true');
});
