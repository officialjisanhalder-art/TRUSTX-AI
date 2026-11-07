/**
 * TRUSTX AI - Content Script
 * Displays high-precision security alert banner when threats are detected.
 */

// Inject global styles once
const styleTag = document.createElement('style');
styleTag.textContent = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

  @keyframes tx-slideIn {
    from { opacity: 0; transform: translateY(-20px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes tx-slideOut {
    from { opacity: 1; transform: translateY(0); }
    to   { opacity: 0; transform: translateY(-20px); }
  }

  #trustx-alert-card {
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 2147483647;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    animation: tx-slideIn 0.25s ease-out forwards;
    min-width: 380px;
    max-width: 500px;
    background: #0b0f19;
    border-radius: 12px;
    overflow: hidden;
    cursor: default;
    box-shadow: 0 16px 32px rgba(0, 0, 0, 0.6);
  }
  #trustx-alert-card.tx-exit {
    animation: tx-slideOut 0.2s ease-in forwards;
  }
  .tx-card-critical {
    border: 1px solid #dc2626;
  }
  .tx-card-medium {
    border: 1px solid #d97706;
  }
  .tx-inner {
    padding: 18px 20px 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .tx-top-row {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .tx-icon-wrap {
    width: 42px;
    height: 42px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }
  .tx-icon-critical { background: rgba(220, 38, 38, 0.15); border: 1px solid #dc2626; color: #f87171; }
  .tx-icon-medium   { background: rgba(217, 119, 6, 0.15); border: 1px solid #d97706; color: #fbbf24; }
  .tx-text-block { flex: 1; }
  .tx-brand {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 3px;
  }
  .tx-brand-critical { color: #f87171; }
  .tx-brand-medium   { color: #fbbf24; }
  .tx-title {
    font-size: 14px;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.3;
  }
  .tx-subtitle {
    font-size: 12px;
    color: #94a3b8;
    margin-top: 3px;
  }
  .tx-dismiss {
    background: transparent;
    border: 1px solid #334155;
    color: #94a3b8;
    border-radius: 6px;
    width: 28px;
    height: 28px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
  }
  .tx-dismiss:hover { background: #1e293b; color: #fff; }
  .tx-divider {
    height: 1px;
    background: #1e293b;
  }
  .tx-actions {
    display: flex;
    gap: 8px;
  }
  .tx-btn-back {
    flex: 2;
    padding: 9px 14px;
    border-radius: 6px;
    border: none;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    background: #dc2626;
    color: #fff;
    transition: opacity 0.2s;
  }
  .tx-btn-back:hover { opacity: 0.9; }
  .tx-btn-proceed {
    flex: 1;
    padding: 9px 12px;
    border-radius: 6px;
    border: 1px solid #334155;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    background: #1e293b;
    color: #94a3b8;
  }
  .tx-btn-proceed:hover { background: #334155; color: #fff; }
  .tx-confidence-bar {
    height: 4px;
    border-radius: 2px;
    background: #1e293b;
    overflow: hidden;
    margin-top: 6px;
  }
  .tx-confidence-fill-critical {
    height: 100%;
    background: #dc2626;
  }
  .tx-confidence-fill-medium {
    height: 100%;
    background: #d97706;
  }

  /* Link Hover Badge */
  #trustx-link-hover-badge {
    position: fixed;
    z-index: 2147483647;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 11px;
    font-weight: 600;
    line-height: 1.4;
    padding: 6px 11px;
    background: #0b0f19;
    border-radius: 6px;
    color: #f8fafc;
    pointer-events: none;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    gap: 8px;
    transition: opacity 0.15s ease;
    white-space: nowrap;
    max-width: 380px;
  }
  #trustx-link-hover-badge.badge-scanning {
    border: 1px solid #334155;
    color: #94a3b8;
  }
  #trustx-link-hover-badge.badge-safe {
    border: 1px solid #16a34a;
    background: #0b0f19;
  }
  #trustx-link-hover-badge.badge-safe .tx-badge-dot {
    background: #16a34a;
  }
  #trustx-link-hover-badge.badge-caution {
    border: 1px solid #d97706;
    background: #0b0f19;
  }
  #trustx-link-hover-badge.badge-caution .tx-badge-dot {
    background: #d97706;
  }
  #trustx-link-hover-badge.badge-danger {
    border: 1px solid #dc2626;
    background: #1e1115;
    color: #fca5a5;
  }
  #trustx-link-hover-badge.badge-danger .tx-badge-dot {
    background: #dc2626;
  }
  .tx-badge-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  /* Zero-Click Phishing Guard Intercept Modal */
  #trustx-intercept-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(3, 7, 18, 0.85);
    backdrop-filter: blur(4px);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  .tx-modal-box {
    background: #0b0f19;
    border: 2px solid #dc2626;
    border-radius: 12px;
    max-width: 520px;
    width: 100%;
    padding: 26px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85);
    color: #f8fafc;
    animation: tx-slideIn 0.2s ease-out;
  }
  .tx-modal-header {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 16px;
  }
  .tx-modal-icon {
    font-size: 28px;
    background: rgba(220, 38, 38, 0.15);
    border: 1px solid #dc2626;
    padding: 10px;
    border-radius: 8px;
    line-height: 1;
  }
  .tx-modal-title {
    font-size: 17px;
    font-weight: 700;
    color: #f8fafc;
    margin: 0 0 4px 0;
  }
  .tx-modal-subtitle {
    font-size: 13px;
    color: #f87171;
    margin: 0;
    font-weight: 600;
  }
  .tx-modal-desc {
    font-size: 13px;
    color: #94a3b8;
    line-height: 1.5;
    margin-bottom: 18px;
  }
  .tx-modal-url-box {
    background: #111726;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 10px 14px;
    font-family: monospace;
    font-size: 12px;
    color: #38bdf8;
    word-break: break-all;
    margin-bottom: 20px;
  }
  .tx-modal-actions {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .tx-btn-stay-safe {
    background: #16a34a;
    color: #fff;
    border: none;
    padding: 11px 16px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    text-align: center;
  }
  .tx-btn-stay-safe:hover { background: #15803d; }
  .tx-btn-deep-scan {
    background: #2563eb;
    color: #fff;
    border: none;
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    text-align: center;
  }
  .tx-btn-deep-scan:hover { background: #1d4ed8; }
  .tx-btn-bypass {
    background: transparent;
    color: #64748b;
    border: none;
    font-size: 11px;
    cursor: pointer;
    text-align: center;
    text-decoration: underline;
    margin-top: 4px;
  }
  .tx-btn-bypass:hover { color: #94a3b8; }
`;
document.head.appendChild(styleTag);

// Listen for scan results from background worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_RESULT') {
    const result = message.data;
    if (result.risk_level === 'high' || result.risk_level === 'critical') {
      showWarningBanner(result);
    } else if (result.risk_level === 'medium') {
      showCautionBanner(result);
    }
  }
});

/**
 * Display card for high/critical risk URLs.
 */
function showWarningBanner(result) {
  removeBanner();

  const card = document.createElement('div');
  card.id = 'trustx-alert-card';
  card.className = 'tx-card-critical';
  card.innerHTML = `
    <div class="tx-inner">
      <div class="tx-top-row">
        <div class="tx-icon-wrap tx-icon-critical">🚨</div>
        <div class="tx-text-block">
          <div class="tx-brand tx-brand-critical">TRUSTX AI · ${result.risk_level.toUpperCase()} THREAT</div>
          <div class="tx-title">Phishing Website Flagged</div>
          <div class="tx-subtitle">Confidence: <strong>${result.confidence}%</strong></div>
          <div class="tx-confidence-bar">
            <div class="tx-confidence-fill-critical" style="width:${result.confidence}%"></div>
          </div>
        </div>
        <button class="tx-dismiss" id="tx-dismiss-btn" title="Dismiss">✕</button>
      </div>
      <div class="tx-divider"></div>
      <div class="tx-actions">
        <button class="tx-btn-back" onclick="window.history.back()">← Go Back (Safe)</button>
        <button class="tx-btn-proceed" id="tx-proceed-btn">Proceed Anyway</button>
      </div>
    </div>
  `;

  document.body.prepend(card);
  document.getElementById('tx-dismiss-btn')?.addEventListener('click', removeBanner);
  document.getElementById('tx-proceed-btn')?.addEventListener('click', removeBanner);
}

/**
 * Display card for medium-risk URLs.
 */
function showCautionBanner(result) {
  removeBanner();

  const card = document.createElement('div');
  card.id = 'trustx-alert-card';
  card.className = 'tx-card-medium';
  card.innerHTML = `
    <div class="tx-inner">
      <div class="tx-top-row">
        <div class="tx-icon-wrap tx-icon-medium">⚠️</div>
        <div class="tx-text-block">
          <div class="tx-brand tx-brand-medium">TRUSTX AI · MEDIUM RISK</div>
          <div class="tx-title">Proceed with Caution</div>
          <div class="tx-subtitle">Confidence: <strong>${result.confidence}%</strong></div>
          <div class="tx-confidence-bar">
            <div class="tx-confidence-fill-medium" style="width:${result.confidence}%"></div>
          </div>
        </div>
        <button class="tx-dismiss" id="tx-dismiss-btn" title="Dismiss">✕</button>
      </div>
      <div class="tx-divider"></div>
      <div class="tx-actions">
        <button class="tx-btn-back" onclick="window.history.back()">← Go Back (Safe)</button>
        <button class="tx-btn-proceed" id="tx-proceed-btn">Proceed</button>
      </div>
    </div>
  `;

  document.body.prepend(card);
  document.getElementById('tx-dismiss-btn')?.addEventListener('click', removeBanner);
  document.getElementById('tx-proceed-btn')?.addEventListener('click', removeBanner);
}

function removeBanner() {
  const existing = document.getElementById('trustx-alert-card');
  if (existing) {
    existing.classList.add('tx-exit');
    setTimeout(() => existing.remove(), 200);
  }
}

// ============================================================
// TRUSTX AI: Link Hover Threat Detection & Zero-Click Guard
// ============================================================

const localLinkCache = new Map();
let hoverTimeout = null;
let currentHoveredAnchor = null;
let activeBadge = null;

let lastMouseX = 0;
let lastMouseY = 0;

document.addEventListener('mousemove', (e) => {
  lastMouseX = e.clientX;
  lastMouseY = e.clientY;
  if (activeBadge) {
    positionBadge(activeBadge, lastMouseX, lastMouseY);
  }
}, { passive: true });

function positionBadge(badge, x, y) {
  const badgeWidth = badge.offsetWidth || 220;
  const badgeHeight = badge.offsetHeight || 32;
  let posX = x + 14;
  let posY = y + 16;
  if (posX + badgeWidth > window.innerWidth - 12) {
    posX = x - badgeWidth - 12;
  }
  if (posY + badgeHeight > window.innerHeight - 12) {
    posY = y - badgeHeight - 12;
  }
  badge.style.left = `${Math.max(10, posX)}px`;
  badge.style.top = `${Math.max(10, posY)}px`;
}

function getValidLinkUrl(element) {
  if (!element || typeof element.closest !== 'function') return null;
  const anchor = element.closest('a[href]');
  if (!anchor) return null;
  const rawHref = anchor.getAttribute('href');
  if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:') || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) {
    return null;
  }
  try {
    const resolved = new URL(rawHref, window.location.href);
    if (!['http:', 'https:'].includes(resolved.protocol)) return null;
    return { anchor, url: resolved.href, domain: resolved.hostname };
  } catch (err) {
    return null;
  }
}

// 1. Mouseover listener: debounced hover detection
document.addEventListener('mouseover', (e) => {
  const linkInfo = getValidLinkUrl(e.target);
  if (!linkInfo) return;

  currentHoveredAnchor = linkInfo.anchor;
  clearTimeout(hoverTimeout);

  hoverTimeout = setTimeout(() => {
    if (currentHoveredAnchor !== linkInfo.anchor) return;
    showLinkHoverBadge(linkInfo.url, linkInfo.domain);
  }, 160);
});

// 2. Mouseout listener: cancel and remove badge
document.addEventListener('mouseout', (e) => {
  const linkInfo = getValidLinkUrl(e.target);
  if (linkInfo && linkInfo.anchor === currentHoveredAnchor) {
    clearTimeout(hoverTimeout);
    currentHoveredAnchor = null;
    removeLinkHoverBadge();
  }
});

function showLinkHoverBadge(url, domain) {
  removeLinkHoverBadge();

  activeBadge = document.createElement('div');
  activeBadge.id = 'trustx-link-hover-badge';
  activeBadge.className = 'badge-scanning';
  activeBadge.innerHTML = `<span class="tx-badge-dot" style="background:#64748b;"></span> 🛡️ TRUSTX AI · Verifying ${domain}...`;
  document.body.appendChild(activeBadge);
  positionBadge(activeBadge, lastMouseX, lastMouseY);

  if (localLinkCache.has(url)) {
    renderBadgeResult(activeBadge, localLinkCache.get(url), domain);
    return;
  }

  try {
    chrome.runtime.sendMessage({ type: 'SCAN_LINK_HOVER', url }, (res) => {
      if (chrome.runtime.lastError || !res || res.disabled) {
        removeLinkHoverBadge();
        return;
      }
      localLinkCache.set(url, res);
      if (activeBadge && currentHoveredAnchor) {
        renderBadgeResult(activeBadge, res, domain);
      }
    });
  } catch (err) {
    removeLinkHoverBadge();
  }
}

function renderBadgeResult(badge, res, domain) {
  if (!badge) return;
  const isPhishing = res.prediction === 'phishing' || res.risk_level === 'critical' || res.risk_level === 'high';
  const isMedium = res.risk_level === 'medium';

  if (isPhishing) {
    badge.className = 'badge-danger';
    badge.innerHTML = `<span class="tx-badge-dot"></span> 🚨 <strong>PHISHING BLOCKED</strong> · ${domain} (${res.confidence || 95}%)`;
  } else if (isMedium) {
    badge.className = 'badge-caution';
    badge.innerHTML = `<span class="tx-badge-dot"></span> ⚠️ <strong>SUSPICIOUS LINK</strong> · ${domain} (${res.confidence || 70}%)`;
  } else {
    badge.className = 'badge-safe';
    badge.innerHTML = `<span class="tx-badge-dot"></span> 🛡️ <strong>Safe Link</strong> · ${domain} (${res.confidence || 99}%)`;
  }
  positionBadge(badge, lastMouseX, lastMouseY);
}

function removeLinkHoverBadge() {
  if (activeBadge) {
    activeBadge.remove();
    activeBadge = null;
  }
}

// 3. Click Interception: Zero-Click Phishing Guard
document.addEventListener('click', (e) => {
  const linkInfo = getValidLinkUrl(e.target);
  if (!linkInfo) return;

  const { url, domain, anchor } = linkInfo;
  const cached = localLinkCache.get(url);

  if (cached) {
    const isThreat = cached.prediction === 'phishing' || cached.risk_level === 'critical' || cached.risk_level === 'high';
    if (isThreat) {
      e.preventDefault();
      e.stopPropagation();
      removeLinkHoverBadge();
      showClickInterceptModal(url, domain, cached);
      return;
    }
    // Safe link cached - allow instantaneous normal navigation
    return;
  }

  // If not cached yet, pause navigation momentarily to inspect target
  e.preventDefault();
  e.stopPropagation();
  removeLinkHoverBadge();

  const tempBadge = document.createElement('div');
  tempBadge.id = 'trustx-link-hover-badge';
  tempBadge.className = 'badge-scanning';
  tempBadge.innerHTML = `<span class="tx-badge-dot" style="background:#38bdf8;"></span> 🛡️ TRUSTX AI: Verifying link safety...`;
  document.body.appendChild(tempBadge);
  positionBadge(tempBadge, lastMouseX, lastMouseY);

  try {
    chrome.runtime.sendMessage({ type: 'SCAN_LINK_CLICK', url }, (res) => {
      tempBadge.remove();
      if (chrome.runtime.lastError || !res || res.disabled || res.prediction === 'error') {
        navigateTo(url, anchor.target);
        return;
      }

      localLinkCache.set(url, res);
      const isThreat = res.prediction === 'phishing' || res.risk_level === 'critical' || res.risk_level === 'high';

      if (isThreat) {
        showClickInterceptModal(url, domain, res);
      } else {
        navigateTo(url, anchor.target);
      }
    });
  } catch (err) {
    tempBadge.remove();
    navigateTo(url, anchor.target);
  }
}, true); // Capture phase is critical

function navigateTo(url, target) {
  if (target === '_blank') {
    window.open(url, '_blank', 'noopener,noreferrer');
  } else {
    window.location.href = url;
  }
}

function showClickInterceptModal(url, domain, res) {
  document.getElementById('trustx-intercept-backdrop')?.remove();

  const backdrop = document.createElement('div');
  backdrop.id = 'trustx-intercept-backdrop';

  const riskLabel = (res.risk_level || 'critical').toUpperCase();
  const confidence = res.confidence ? `${res.confidence}%` : 'High';

  backdrop.innerHTML = `
    <div class="tx-modal-box">
      <div class="tx-modal-header">
        <div class="tx-modal-icon">🚨</div>
        <div>
          <h2 class="tx-modal-title">TRUSTX AI — Phishing Link Blocked</h2>
          <p class="tx-modal-subtitle">${riskLabel} THREAT INTERCEPTED · ZERO-CLICK GUARD</p>
        </div>
      </div>
      <p class="tx-modal-desc">
        TRUSTX AI intercepted this navigation because the destination URL matches known phishing heuristics, deceptive lookalike domain spoofing, or active threat intelligence.
      </p>
      <div class="tx-modal-url-box">${url}</div>
      <div style="font-size: 12px; color: #94a3b8; margin-bottom: 18px;">
        Classification: <strong style="color: #f87171;">Phishing Website</strong> · Confidence: <strong style="color: #fff;">${confidence}</strong>
      </div>
      <div class="tx-modal-actions">
        <button class="tx-btn-stay-safe" id="tx-modal-safe-btn">🛡️ Cancel & Stay on Current Page (Recommended)</button>
        <button class="tx-btn-deep-scan" id="tx-modal-deep-btn">🔬 View Full AI Security Investigation</button>
        <button class="tx-btn-bypass" id="tx-modal-bypass-btn">I understand the risk, proceed to website</button>
      </div>
    </div>
  `;

  document.body.appendChild(backdrop);

  document.getElementById('tx-modal-safe-btn')?.addEventListener('click', () => {
    backdrop.remove();
  });

  document.getElementById('tx-modal-deep-btn')?.addEventListener('click', () => {
    backdrop.remove();
    window.open(`http://localhost:5173/scanner?target=${encodeURIComponent(url)}`, '_blank');
  });

  document.getElementById('tx-modal-bypass-btn')?.addEventListener('click', () => {
    if (confirm('WARNING: This website has been flagged as malicious. Are you certain you want to proceed?')) {
      backdrop.remove();
      window.location.href = url;
    }
  });
}
