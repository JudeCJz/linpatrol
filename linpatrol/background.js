// Import scripts for large database modularity
importScripts('database.js');

const LM_STUDIO_URL = 'http://localhost:1234/v1/chat/completions';
const MODEL_ID = 'qwen-4b'; // Specifically requested 4B model

// Maintain a set of suspicious URLs for context menu targeting
let suspiciousUrls = new Set();

// 1. Initial Intelligence Database Flash-Sync
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["blacklist", "whitelist", "keywords", "suspiciousTlds", "dangerousExtensions", "urlShorteners"], (res) => {
    // Only pre-fill if the database is currently empty
    if (!res.blacklist || res.blacklist.length === 0) {
      chrome.storage.local.set({
        blacklist: INITIAL_DATABASE.blacklist,
        whitelist: INITIAL_DATABASE.whitelist,
        keywords: INITIAL_DATABASE.keywords,
        suspiciousTlds: INITIAL_DATABASE.suspiciousTlds,
        dangerousExtensions: INITIAL_DATABASE.dangerousExtensions,
        urlShorteners: INITIAL_DATABASE.urlShorteners,
        isScanningEnabled: true
      }, () => {
        syncDatabaseToNetworkShield();
      });
      console.log("LinPatrol One Intelligence Database synchronized.");
    } else {
      syncDatabaseToNetworkShield();
    }
  });
});

// 2. High-Fidelity Network-Level Pre-Navigation Shielding
// Now redirects to blocked.html with the URL context instead of showing a generic error page
async function syncDatabaseToNetworkShield() {
  chrome.storage.local.get(["blacklist", "isScanningEnabled"], (res) => {
    if (res.isScanningEnabled === false) {
      chrome.declarativeNetRequest.getDynamicRules(rules => {
        const ruleIds = rules.map(r => r.id);
        if (ruleIds.length > 0) {
          chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ruleIds });
        }
      });
      return;
    }

    const blacklist = res.blacklist || [];
    
    // Create redirection rules (showing our custom blocked.html UI)
    const newRules = blacklist.slice(0, 50).map((domain, index) => ({
      id: 1000 + index, // Dedicated high-id range for user rules
      priority: 100,    // Extreme priority to override everything
      action: { 
        type: "redirect", 
        redirect: { extensionPath: `/blocked.html?url=${encodeURIComponent(domain)}` } 
      },
      condition: {
        urlFilter: domain, // DNR handles partial domain matches elegantly
        resourceTypes: ["main_frame"]
      }
    }));

    chrome.declarativeNetRequest.getDynamicRules(existing => {
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existing.map(r => r.id),
        addRules: newRules
      });
    });
  });
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") {
     syncDatabaseToNetworkShield(); 
  }
});

// 3. Status Management
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "UPDATE_STATUS") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    if (tabId) {
      let badgeText = "✓"; // Default to tick
      let color = "#64748b"; // Default grey
      
      const scoreNum = parseFloat(request.score || "0");
      
      if (request.status === "OFF" || !request.score) {
        badgeText = "";
        color = "#64748b";
      } else if (scoreNum > 6.0 || request.status === "DANGER") {
        badgeText = "X"; // New High-Risk Icon
        color = "#ef4444"; // Red Scale
      } else if (scoreNum >= 1.0) {
        badgeText = "✓";
        color = "#f59e0b"; // Yellow Scale
      } else {
        badgeText = "✓";
        color = "#22c55e"; // Green Scale (Safe)
      }

      chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
    }
  }

  // Handle AI analysis requests from content scripts and popup
  if (request.type === "AI_GET_VERDICT") {
    getAiVerdict(request.url, request.metadata)
      .then(sendResponse)
      .catch((error) => sendResponse({ error: error.message }));
    return true; // Keep channel open
  }

  // Handle general AI chat from popup
  if (request.type === "AI_CHAT") {
    processChat(request.query)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  // Update suspicious URLs set for context menu filtering
  if (request.type === "REGISTER_SUSPICIOUS_LINKS") {
    request.urls.forEach(u => suspiciousUrls.add(u));
    updateContextMenu();
  }
});

// 4. AI Engine: LM Studio Integration (Qwen) with Concurrency Control
const aiQueue = [];
let activeRequests = 0;
const MAX_CONCURRENT_REQUESTS = 3;

async function processQueue() {
  while (activeRequests < MAX_CONCURRENT_REQUESTS && aiQueue.length > 0) {
    activeRequests++;
    const { url, metadata, resolve, reject } = aiQueue.shift();
    
    (async () => {
      try {
        const result = await performAiFetch(url, metadata);
        resolve(result);
      } catch (err) {
        reject(err);
      } finally {
        activeRequests--;
        processQueue();
      }
    })();
  }
}

async function getAiVerdict(url, metadata = {}) {
  return new Promise((resolve, reject) => {
    aiQueue.push({ url, metadata, resolve, reject });
    processQueue();
  });
}

async function performAiFetch(url, metadata = {}) {
  const prompt = `System: You are LinPatrol Cybersecurity AI. Analyze the URL and context.
Provide a definitive verdict: SAFE or UNSAFE.
Provide a 1-sentence reason starting with "REASON: ".

Link: ${url}
Context: ${JSON.stringify(metadata)}

Response format:
VERDICT: [SAFE or UNSAFE]
REASON: [Specific reason why it is safe or unsafe]`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000); // Increased timeout to 12s for Qwen-4B

    const response = await fetch(LM_STUDIO_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: MODEL_ID,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
        max_tokens: 150
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    const content = data.choices[0]?.message?.content || "";
    
    // Improved detection logic
    const isUnsafe = /UNSAFE/i.test(content) || /MALICIOUS/i.test(content) || /DANGER/i.test(content);
    
    let reasonLine = "No immediate threats detected.";
    const matches = content.match(/REASON:\s*(.*)/i);
    if (matches && matches[1]) {
      reasonLine = matches[1].replace(/[\[\]]/g, '').trim();
    } else {
      const lines = content.split('\n').filter(l => l.trim().length > 5);
      if (lines.length > 0) reasonLine = lines[lines.length - 1].trim();
    }

    return { 
      safe: !isUnsafe, 
      reason: reasonLine.slice(0, 100)
    };
  } catch (err) {
    console.error("LinPatrol AI Error:", err);
    return { 
      safe: true, // Fail-safe to avoid blocking everything accidentally
      reason: "Analysis error (AI Offline)." 
    };
  }
}

async function processChat(query) {
  const prompt = `System: You are LinPatrol AI, a cybersecurity expert. Provide a VERY BRIEF response (max 2-3 lines). Be precise and professional.
User Query: ${query}`;

  try {
    const response = await fetch(LM_STUDIO_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: MODEL_ID,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.7,
        max_tokens: 150
      })
    });

    const data = await response.json();
    let content = data.choices[0].message.content.trim();
    
    // Final enforcement of the 2-3 line rule
    const lines = content.split('\n').filter(l => l.trim()).slice(0, 3);
    return { content: lines.join('\n') };
  } catch (err) {
    return { content: "I'm currently unable to connect to my local intelligence engine (LM Studio). Please ensure it's running on port 1234." };
  }
}

// 5. AI-Driven Context Menu
function updateContextMenu() {
  chrome.contextMenus.removeAll(() => {
    if (suspiciousUrls.size === 0) return;

    // Filter out invalid URL patterns (only http/https)
    const patterns = Array.from(suspiciousUrls)
      .filter(u => u.startsWith('http'))
      .map(u => u.replace(/[?#].*$/, '') + '*'); // Wildcard for params

    if (patterns.length === 0) return;

    chrome.contextMenus.create({
      id: "linpatrol-ai-why",
      title: "LinPatrol AI: Why is this link unsafe?",
      contexts: ["link"],
      targetUrlPatterns: patterns.slice(0, 100) // Limited for performance
    });
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "linpatrol-ai-why") {
    getAiVerdict(info.linkUrl).then(result => {
      chrome.tabs.sendMessage(tab.id, {
        type: "AI_SHOW_ALERT",
        url: info.linkUrl,
        verdict: result.safe ? "SAFE" : "UNSAFE",
        reason: result.reason
      });
    });
  }
});

// 4. Side Panel Control: Anchoring the UI to the border
// Ensures LinPatrol opens as a professional sidebar on the right
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch((error) => console.error(error));

chrome.action.onClicked.addListener((tab) => {
  chrome.sidePanel.open({ tabId: tab.id });
});
// 5. Global Command Support: Fast Toggling
chrome.commands.onCommand.addListener((command) => {
  if (command === "toggle-scanning") {
    chrome.storage.local.get(["isScanningEnabled"], (res) => {
      const nextState = res.isScanningEnabled === false;
      chrome.storage.local.set({ isScanningEnabled: nextState }, () => {
        // Update Network-Level Rules
        syncDatabaseToNetworkShield();
        
        // Refresh the active tab to apply the state change immediately
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
             chrome.tabs.reload(tabs[0].id);
          }
        });
        
        console.log(`LinPatrol Shield: ${nextState ? "ACTIVE" : "DISABLED"}`);
      });
    });
  }
});
