let scannedLinks = [];
let isScanningEnabled = null;
let isCurrentSiteDangerous = false;

// IntersectionObserver for viewport-based dynamic scanning
let viewportObserver = null;
const visibleLinks = new Set();
const analyzedLinks = new Map(); // Map to store analysis results

// Maintain local cache of security settings
let securitySettings = {
  blacklist: [],
  whitelist: [],
  keywords: [],
  suspiciousTlds: [],
  sensitiveBrands: [],
  dangerousExtensions: [],
  urlShorteners: []
};

// [Expert Security Shield] - Immediate Execution
const applyShield = (el) => {
  if (document.getElementById("LinPatrol-shield")) return;
  const shield = document.createElement("style");
  shield.id = "LinPatrol-shield";
  shield.textContent = "html { display: none !important; }";
  el.appendChild(shield);
};

if (document.documentElement) {
  applyShield(document.documentElement);
}

function restoreVisibility() {
  const shield = document.getElementById("LinPatrol-shield");
  if (shield) shield.remove();
}

const extractDomain = (urlStr) => {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch (error) {
    if (urlStr.startsWith("www.")) return urlStr.split("/")[0].toLowerCase();
    return "";
  }
};

function setupDynamicScanning() {
  if (!viewportObserver) {
    viewportObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const link = entry.target;
          const url = link.href || link.dataset.lssHref;
          if (url && !analyzedLinks.has(url)) {
            analyzeLink(link);
          }
        }
      });
    }, { threshold: 0.1, rootMargin: "250px" });
  }

  // Initial batch observation
  const links = getAllLinksRecursively(document);
  links.forEach(link => {
    try { viewportObserver.observe(link); } catch(e) {}
  });
}

function isWhitelisted(urlOrDomain) {
  const domain = extractDomain(urlOrDomain);
  if (!domain) return false;
  return securitySettings.whitelist.some(item => 
    domain === item.toLowerCase() || domain.endsWith(`.${item.toLowerCase()}`)
  );
}

async function analyzeLink(link) {
  if (!isScanningEnabled) return;
  const url = link.href || link.dataset.lssHref;
  if (!url || analyzedLinks.has(url)) return;

  // 1. Instant Whitelist Check (Efficiency)
  if (isWhitelisted(url)) {
    analyzedLinks.set(url, { safe: true, url: url });
    return;
  }

  // 2. AI-First Scanning Policy
  const linkText = (link.innerText || link.title || "").trim().slice(0, 150);
  
  if (!chrome.runtime?.id) return; // Prevent "Extension context invalidated" errors

  try {
    chrome.runtime.sendMessage({ 
      type: "AI_GET_VERDICT", 
      url: url, 
      metadata: { 
        linkText: linkText,
        pageDomain: window.location.hostname,
        isInternal: extractDomain(url) === window.location.hostname
      } 
    }, (aiResult) => {
      if (chrome.runtime?.lastError) {
        console.warn("LinPatrol: Context invalidated, stopping scan.");
        return;
      }
      
      if (aiResult) {
        applyVerdict(link, aiResult);
      }
    });
  } catch (e) {
    console.warn("LinPatrol: Communication failed (Context invalidated)");
  }
}

function applyVerdict(link, result) {
  const url = link.href || link.dataset.lssHref;
  analyzedLinks.set(url, { ...result, url: url });
  
  // Remove existing reason tags if any
  const existingTag = link.parentElement?.querySelector(`.lss-reason-tag[data-for="${url}"]`);
  if (existingTag) existingTag.remove();

  if (!result.safe) {
    link.classList.add("lss-unsafe-link");
    link.dataset.lssReason = result.reason;
    
    // Aesthetic Highlighting
    link.style.outline = "3px solid #ef4444";
    link.style.backgroundColor = "rgba(239, 68, 68, 0.2)";
    link.style.borderRadius = "4px";
    link.style.padding = "1px 4px";
    
    // Context Display: Inject Reason Tag Underneath
    const reasonTag = document.createElement("span");
    reasonTag.className = "lss-reason-tag";
    reasonTag.dataset.for = url;
    reasonTag.innerText = `⚠ ${result.reason}`;
    
    // Position the tag logically
    if (link.nextSibling) {
      link.parentElement.insertBefore(reasonTag, link.nextSibling);
    } else {
      link.parentElement.appendChild(reasonTag);
    }
    
    link.onmouseenter = (e) => showTooltip(link, result.reason, e);
    link.onmouseleave = () => hideTooltip();
  } else {
    link.classList.remove("lss-unsafe-link");
    delete link.dataset.lssReason;
    link.style.outline = "";
    link.style.backgroundColor = "";
  }
  
  notifyStatus("UPDATE", Array.from(analyzedLinks.values()));
}

function getAllLinksRecursively(root) {
  let allLinks = [];
  const findLinks = (node) => {
    if (!node) return;
    
    // Handle standard links and custom attributed links
    if (node.tagName === "A" && node.href) {
      allLinks.push(node);
    } else if (node.dataset && node.dataset.lssHref) {
      allLinks.push(node);
    }
    
    // Shadow DOM Support
    if (node.shadowRoot) findLinks(node.shadowRoot);
    
    // Iframe Support (if same-origin)
    if (node.tagName === "IFRAME") {
      try { 
        if (node.contentDocument && node.contentDocument.body) {
          findLinks(node.contentDocument.body);
        }
      } catch (e) {}
    }
    
    let child = node.firstElementChild;
    while (child) {
      findLinks(child);
      child = child.nextElementSibling;
    }
  };
  
  findLinks(root.body || root);
  return allLinks;
}

// [HEAVY DUTY] - Scan for raw text URLs in messages (e.g. Gmail)
function scanTextForLinks(root) {
  const urlRegex = /(https?:\/\/[^\s<]+[^<.,:;"')\]\s])/gi;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
  let textNode;
  const nodesToReplace = [];

  while (textNode = walker.nextNode()) {
    if (["SCRIPT", "STYLE", "A", "TEXTAREA"].includes(textNode.parentElement.tagName)) continue;
    if (urlRegex.test(textNode.nodeValue)) {
      nodesToReplace.push(textNode);
    }
  }

  nodesToReplace.forEach(node => {
    const val = node.nodeValue;
    const parent = node.parentElement;
    if (!parent) return;

    const fragment = document.createDocumentFragment();
    let lastIndex = 0;
    const newSpans = [];
    
    val.replace(urlRegex, (url, index) => {
      fragment.appendChild(document.createTextNode(val.substring(lastIndex, index)));
      const span = document.createElement("span");
      span.className = "lss-text-link lss-scanned";
      span.dataset.lssHref = url;
      span.innerText = url;
      span.style.textDecoration = "underline";
      span.style.cursor = "pointer";
      span.style.color = "#38bdf8";
      fragment.appendChild(span);
      newSpans.push(span);
      lastIndex = index + url.length;
    });
    fragment.appendChild(document.createTextNode(val.substring(lastIndex)));
    
    try { 
      parent.replaceChild(fragment, node); 
      // Observe new spans immediately
      newSpans.forEach(span => {
        if (viewportObserver) viewportObserver.observe(span);
      });
    } catch(e) {}
  });
}

const mutationObserver = new MutationObserver((mutations) => {
  if (!isScanningEnabled) return;
  
  let addedSomething = false;
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node.nodeType === 1) {
        // Only scan if not already processed
        if (node.classList?.contains('lss-scanned')) continue;
        
        const links = getAllLinksRecursively(node);
        links.forEach(l => {
          if (viewportObserver) viewportObserver.observe(l);
          addedSomething = true;
        });
      }
    }
  }
  
  if (addedSomething && window.location.hostname.includes("mail.google.com")) {
    scanTextForLinks(document.body);
  }
});

let activeTooltip = null;
function showTooltip(link, reason, e) {
  hideTooltip();
  activeTooltip = document.createElement("div");
  activeTooltip.className = "lss-tooltip";
  activeTooltip.innerHTML = `<strong>LinPatrol Analysis</strong>${reason}<br><span class="lss-url">${link.href || link.dataset.lssHref}</span>`;
  document.body.appendChild(activeTooltip);
  const rect = link.getBoundingClientRect();
  activeTooltip.style.top = `${window.scrollY + rect.bottom + 8}px`;
  activeTooltip.style.left = `${window.scrollX + rect.left}px`;
}

function hideTooltip() {
  if (activeTooltip) { activeTooltip.remove(); activeTooltip = null; }
}

function notifyStatus(status, links = []) {
  if (!chrome.runtime?.id) return;
  const unsafeCount = links.filter(l => !l.safe).length;
  const score = links.length > 0 ? (unsafeCount / links.length) * 10 : 0;
  chrome.runtime.sendMessage({ 
    type: "UPDATE_STATUS", 
    status, 
    score: score.toFixed(1) 
  }).catch(() => {});
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATS") {
    const links = Array.from(analyzedLinks.values());
    sendResponse({
      totalLinks: links.length,
      unsafeLinks: links.filter(l => !l.safe).length,
      scannedLinks: links,
      isScanningEnabled: isScanningEnabled
    });
  } else if (request.type === "FORCE_RESCAN") {
    analyzedLinks.clear();
    document.querySelectorAll(".lss-reason-tag").forEach(t => t.remove());
    setupDynamicScanning();
    if (window.location.hostname.includes("mail.google.com")) scanTextForLinks(document.body);
    sendResponse({ success: true });
  } else if (request.type === "AI_SHOW_ALERT") {
    alert(`[LinPatrol AI] Analysis: ${request.verdict}\n\nReason: ${request.reason}`);
  }
  return true;
});

function kickstart() {
  if (!chrome.runtime?.id) return;
  
  chrome.storage.local.get(
    ["isScanningEnabled", "whitelist"], 
    (res) => {
      isScanningEnabled = res.isScanningEnabled !== false;
      securitySettings.whitelist = res.whitelist || [];
      
      restoreVisibility();
      
      if (isScanningEnabled) {
        setupDynamicScanning();
        mutationObserver.observe(document.body, { childList: true, subtree: true });
        if (window.location.hostname.includes("mail.google.com")) scanTextForLinks(document.body);
      }
    }
  );
}

// Initial start
kickstart();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.isScanningEnabled) {
    isScanningEnabled = changes.isScanningEnabled.newValue !== false;
    if (!isScanningEnabled) {
      document.querySelectorAll(".lss-unsafe-link").forEach(l => {
        l.classList.remove("lss-unsafe-link");
        l.style.outline = "";
        l.style.backgroundColor = "";
      });
      document.querySelectorAll(".lss-reason-tag").forEach(t => t.remove());
      hideTooltip();
    } else {
      setupDynamicScanning();
    }
  }
});
