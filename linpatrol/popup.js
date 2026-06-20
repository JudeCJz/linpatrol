document.addEventListener("DOMContentLoaded", () => {
  const elements = {
    blacklistContainer: document.getElementById("blacklist-view"),
    whitelistContainer: document.getElementById("whitelist-view"),
    scanToggle: document.getElementById("scan-toggle"),
    customUrl: document.getElementById("custom-url"),
    feedback: document.getElementById("popup-feedback"),
    siteStatus: document.getElementById("site-status"),
    totalLinks: document.getElementById("total-links"),
    unsafeLinks: document.getElementById("unsafe-links"),
    threatScore: document.getElementById("threat-score"),
    smartToggleBtn: document.getElementById("smart-toggle-btn"),
    auditContainer: document.getElementById("audit-view")
  };

  const listQueries = {
    blacklist: "",
    whitelist: ""
  };

  initializePopup();
  bindEvents();

  function refreshSmartButton() {
    const hostname = normalizeHostname(elements.customUrl.value);
    if (!hostname) {
      elements.smartToggleBtn.textContent = "ENTER DOMAIN";
      elements.smartToggleBtn.className = "btn btn-outline";
      return;
    }

    chrome.storage.local.get(["blacklist", "whitelist"], (res) => {
      const isBlacklisted = (res.blacklist || []).includes(hostname);
      const isWhitelisted = (res.whitelist || []).includes(hostname);

      if (isBlacklisted) {
        elements.smartToggleBtn.textContent = "TRUST THIS SITE";
        elements.smartToggleBtn.className = "btn btn-success";
      } else if (isWhitelisted) {
        elements.smartToggleBtn.textContent = "BLOCK THIS SITE";
        elements.smartToggleBtn.className = "btn btn-danger";
      } else {
        elements.smartToggleBtn.textContent = "BLOCK THIS SITE";
        elements.smartToggleBtn.className = "btn btn-danger";
      }
    });
  }

  function handleSmartToggle() {
    const hostname = normalizeHostname(elements.customUrl.value);
    if (!hostname) return;

    chrome.storage.local.get(["blacklist", "whitelist"], (res) => {
      const isBlacklisted = (res.blacklist || []).includes(hostname);
      const targetList = isBlacklisted ? "whitelist" : "blacklist";
      updateStorageLists(targetList, hostname);
    });
  }

  function initializePopup() {
    chrome.storage.local.get(
      ["blacklist", "whitelist", "isScanningEnabled"],
      (res) => {
        elements.scanToggle.checked = res.isScanningEnabled !== false;
        renderList("blacklist", res.blacklist || []);
        renderList("whitelist", res.whitelist || []);
        syncWithActiveTab();
      }
    );
  }

  function bindEvents() {
    elements.scanToggle.addEventListener("change", (event) => {
      const isEnabled = event.target.checked;
      chrome.storage.local.set({ isScanningEnabled: isEnabled }, () => {
        setFeedback(
          isEnabled ? "Scanning enabled for the active tab." : "Scanning disabled for the active tab.",
          isEnabled ? "success" : ""
        );
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
          if (tabs[0]?.id) {
            chrome.tabs.reload(tabs[0].id);
          }
          // Automatically close the sidebar when disabled
          if (!isEnabled) {
            setTimeout(() => window.close(), 400);
          }
        });
      });
    });

    elements.smartToggleBtn.addEventListener("click", () => {
      handleSmartToggle();
    });

    elements.customUrl.addEventListener("input", () => {
      refreshSmartButton();
    });

    // Accordion Toggle Logic
    document.querySelectorAll(".accordion-header").forEach(header => {
      header.addEventListener("click", () => {
        const parent = header.parentElement;
        parent.classList.toggle("open");
      });
    });

    elements.customUrl.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        handleSmartToggle();
      }
    });

    // AI Chat UI Controls
    const aiPanel = document.getElementById("ai-chat-panel");
    document.getElementById("open-ai-chat").addEventListener("click", () => aiPanel.classList.add("open"));
    document.getElementById("close-ai-chat").addEventListener("click", () => aiPanel.classList.remove("open"));

    document.getElementById("ai-send").addEventListener("click", handleAiMessage);
    document.getElementById("ai-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleAiMessage();
    });



    // --- Dynamic Tab Sync (Real-time tracking) ---
    // This ensures the side panel updates instantly when you switch tabs
    chrome.tabs.onActivated.addListener(() => syncWithActiveTab());
    
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
      if (changeInfo.status === "complete") syncWithActiveTab();
    });

    document.getElementById("search-blocked").addEventListener("input", (e) => {
      listQueries.blacklist = e.target.value.toLowerCase();
      chrome.storage.local.get(["blacklist"], (res) => renderList("blacklist", res.blacklist || []));
    });

    document.getElementById("search-trusted").addEventListener("input", (e) => {
      listQueries.whitelist = e.target.value.toLowerCase();
      chrome.storage.local.get(["whitelist"], (res) => renderList("whitelist", res.whitelist || []));
    });

    // Real-time HUD Updates
    chrome.runtime.onMessage.addListener((request) => {
      if (request.type === "UPDATE_STATUS") {
        syncWithActiveTab();
      }
    });

    // Fallback polling for high-interaction sites like Gmail
    setInterval(() => syncWithActiveTab(), 3000);
  }



  function handleAiMessage() {
    const input = document.getElementById("ai-input");
    const text = input.value.trim();
    if (!text) return;

    addAiMessage("user", text);
    input.value = "";

    // LinPatrol AI Logic Engine
    setTimeout(() => {
      processAiResponse(text.toLowerCase());
    }, 600);
  }

  function addAiMessage(sender, text) {
    const body = document.getElementById("ai-messages");
    const msg = document.createElement("div");
    msg.className = `ai-message ${sender}`;
    msg.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<b>$1</b>');
    body.appendChild(msg);
    body.scrollTop = body.scrollHeight;
  }

  function processAiResponse(query) {
    chrome.runtime.sendMessage({ type: "AI_CHAT", query }, (response) => {
      const content = response?.content || "No intelligent response received.";
      addAiMessage("bot", content);
    });
  }

  function updateDomainList(targetList) {
    const hostname = normalizeHostname(elements.customUrl.value);
    if (!hostname) {
      setFeedback("Enter a valid domain such as example.com.", "error");
      return;
    }
    updateStorageLists(targetList, hostname);
  }

  function updateStorageLists(targetList, hostname) {
    chrome.storage.local.get(["blacklist", "whitelist"], (res) => {
      // Bulletproof Scrub: Ensure it's GONE from both lists before adding to target
      const cleanBlacklist = (res.blacklist || []).filter(h => h !== hostname);
      const cleanWhitelist = (res.whitelist || []).filter(h => h !== hostname);

      let nextBlacklist = cleanBlacklist;
      let nextWhitelist = cleanWhitelist;

      if (targetList === "blacklist") {
        nextBlacklist = dedupeList([...cleanBlacklist, hostname]);
      } else {
        nextWhitelist = dedupeList([...cleanWhitelist, hostname]);
      }

      chrome.storage.local.set(
        {
          blacklist: nextBlacklist,
          whitelist: nextWhitelist
        },
        () => {
          // [FIREWALL SYNC] Tab Redirect/Reload Logic
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const currentTab = tabs[0];
            if (!currentTab) return;

            if (currentTab.url.includes("blocked.html") && targetList === "whitelist") {
              try {
                const params = new URLSearchParams(new URL(currentTab.url).search);
                const originalUrl = params.get("url");
                if (originalUrl) {
                  const dest = originalUrl.includes("://") ? originalUrl : `https://${originalUrl}`;
                  chrome.tabs.remove(currentTab.id, () => {
                    chrome.tabs.create({ url: dest, active: true });
                  });
                  return;
                }
              } catch (e) {}
            }
            chrome.tabs.reload(currentTab.id);
          });

          // HUD Refresh
          renderList("blacklist", nextBlacklist);
          renderList("whitelist", nextWhitelist);
          elements.customUrl.value = hostname;
          setFeedback(
            targetList === "blacklist" ? `Blocked ${hostname}.` : `Trusted ${hostname}.`,
            "success"
          );
          
          refreshSmartButton();
          syncWithActiveTab({ forceRescan: true });
        }
      );
    });
  }

  function removeFromStorageList(listName, hostname) {
    chrome.storage.local.get([listName], (res) => {
      const nextList = (res[listName] || []).filter((item) => item !== hostname);
      chrome.storage.local.set({ [listName]: nextList }, () => {
        renderList(listName, nextList);
        setFeedback(`Removed ${hostname} from ${listName}.`, "success");
        syncWithActiveTab({ forceRescan: true });
      });
    });
  }

  function renderList(listName, list) {
    const container = listName === "blacklist" ? elements.blacklistContainer : elements.whitelistContainer;
    const query = listQueries[listName];
    
    container.innerHTML = "";

    const filtered = list.filter(item => item.toLowerCase().includes(query));

    if (filtered.length === 0) {
      container.innerHTML = `<div class='list-item' style='color:#64748b'>${query ? 'No matching domains.' : 'No domains stored.'}</div>`;
      return;
    }

    filtered
      .slice()
      .sort((a, b) => a.localeCompare(b))
      .forEach((item) => {
        const row = document.createElement("div");
        row.className = "list-item";
        row.innerHTML = `<span>${item}</span><span class="remove-item" data-list="${listName}" data-item="${item}" title="Remove">x</span>`;
        container.appendChild(row);
      });

    container.querySelectorAll(".remove-item").forEach((button) => {
      button.addEventListener("click", (event) => {
        removeFromStorageList(event.currentTarget.dataset.list, event.currentTarget.dataset.item);
      });
    });
  }

  function syncWithActiveTab(options = {}) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentTab = tabs[0];
      if (!currentTab?.id) {
        updateStatsUI({ status: "OFFLINE", totalLinks: 0, unsafeLinks: 0 });
        return;
      }

      if (currentTab.url) {
        let hostname = normalizeHostname(currentTab.url);
        
        // [FIX] Quarantine Awareness: Detect if we are currently on the LinPatrol Block Screen
        if (currentTab.url.startsWith("chrome-extension://") && currentTab.url.includes("blocked.html")) {
          try {
            const params = new URLSearchParams(new URL(currentTab.url).search);
            const blockedUrl = params.get("url");
            if (blockedUrl) hostname = normalizeHostname(blockedUrl);
          } catch (e) {}
        }

        if (hostname) {
          elements.customUrl.value = hostname;
          refreshSmartButton();
        }
      }

      if (options.forceRescan) {
        chrome.tabs.sendMessage(currentTab.id, { type: "FORCE_RESCAN" }, () => {
          fetchTabStats(currentTab.id);
        });
        return;
      }

      fetchTabStats(currentTab.id);
    });
  }

  function fetchTabStats(tabId) {
    chrome.tabs.sendMessage(tabId, { type: "GET_STATS" }, (response) => {
      if (chrome.runtime.lastError || !response) {
        updateStatsUI({ status: "OFFLINE", totalLinks: 0, unsafeLinks: 0 });
        return;
      }

      // Vital for AI context: sync real-time scan data to storage
      chrome.storage.local.set({ lastScannedLinks: response.scannedLinks || [] });

      let status = "SECURED ✓";
      if (response.isScanningEnabled === false) {
        status = "DISABLED";
      } else if (response.isCurrentSiteDangerous) {
        status = "THREAT DETECTED";
      } else if (response.unsafeLinks > 0) {
        status = "WARNING";
      }

      updateStatsUI({
        status,
        totalLinks: response.totalLinks || 0,
        unsafeLinks: response.unsafeLinks || 0
      });

      renderAuditList(response.scannedLinks || [], tabId, response.isScanningEnabled);
    });
  }

  function renderAuditList(links, tabId, isEnabled) {
    elements.auditContainer.innerHTML = "";
    
    // Filter to show ONLY doubtful or unsafe links as per user request
    const suspiciousLinks = (links || []).filter(l => !l.safe);
    
    if (suspiciousLinks.length === 0) {
      elements.auditContainer.innerHTML = "<div class='list-item' style='color:#64748b'>No suspicious links detected.</div>";
      return;
    }

    // Sort: Unsafe (Likely red) first
    suspiciousLinks.sort((a, b) => (a.safe === b.safe) ? 0 : a.safe ? 1 : -1);

    suspiciousLinks.forEach(link => {
      const item = document.createElement("div");
      item.className = `audit-item unsafe`; // They are all unsafe/suspicious now
      item.innerHTML = `
        <div class="audit-url">${link.url}</div>
        <div class="audit-reason">${link.reason}</div>
      `;
      item.addEventListener("click", () => {
        chrome.tabs.sendMessage(tabId, { type: "SCROLL_TO_LINK", linkId: link.id });
      });
      elements.auditContainer.appendChild(item);
    });
  }

  // --- Dynamic Particle Engine (tsParticles) ---
  let particlesContainer = null;

  async function initParticles() {
    particlesContainer = await tsParticles.load({
      id: "particles-js",
      options: {
        background: { color: "#080a0f" },
        particles: {
          number: { value: 60 },
          color: { value: "#ffffff" },
          links: {
            enable: true,
            distance: 120,
            color: "#0088ff",
            opacity: 0.4,
            width: 1
          },
          move: {
            enable: true,
            speed: 1.2,
            direction: "none",
            outModes: "out"
          },
          size: { value: 2 },
          opacity: { value: 0.5 }
        },
        interactivity: {
          events: { onHover: { enable: true, mode: "grab" } },
          modes: { grab: { distance: 140, links: { opacity: 0.8 } } }
        }
      }
    });
  }

  function updateVisualThreatState(isDangerous, isEnabled = true) {
    if (!particlesContainer) return;

    const options = particlesContainer.options;
    
    if (isEnabled === false) {
      // Disabled Aesthetic: Grey/Dusty, Slow/Static
      options.particles.color.value = "#4b5563";
      options.particles.links.color.value = "#374151";
      options.particles.move.speed = 0.4;
      options.particles.links.width = 1;
    } else if (isDangerous) {
      // Threat Aesthetic: Neon Red, Fast, Aggressive
      options.particles.color.value = "#ff0000";
      options.particles.links.color.value = "#ff0000";
      options.particles.move.speed = 6.5;
      options.particles.links.width = 2;
    } else {
      // Safe Aesthetic: Calm Blue/White, Constellation style
      options.particles.color.value = "#ffffff";
      options.particles.links.color.value = "#0088ff";
      options.particles.move.speed = 1.2;
      options.particles.links.width = 1;
    }
    particlesContainer.refresh();
  }

  function updateStatsUI({ status, totalLinks, unsafeLinks }) {
    elements.totalLinks.textContent = String(totalLinks);
    elements.unsafeLinks.textContent = String(unsafeLinks);
    elements.siteStatus.textContent = status;

    // Calculate Danger Rating out of 10
    let score = 0;
    if (totalLinks > 0) {
      score = (unsafeLinks / totalLinks) * 10;
    }
    // Cap at 10.0 if somehow exceeded (weighted logic placeholder)
    const displayScore = Math.min(score, 10).toFixed(1);
    elements.threatScore.textContent = `${displayScore} / 10`;

    const isDangerous = (status === "THREAT DETECTED" || status === "WARNING");
    const isEnabled = (status !== "DISABLED" && status !== "OFFLINE");
    updateVisualThreatState(isDangerous, isEnabled);

    if (status === "THREAT DETECTED") {
      elements.siteStatus.className = "stat-val dangerous-site";
      elements.threatScore.className = "stat-val dangerous-site";
    } else if (status === "WARNING") {
      elements.siteStatus.className = "stat-val warn-site";
      elements.threatScore.className = "stat-val warn-site";
    } else if (status === "DISABLED" || status === "OFFLINE") {
      elements.siteStatus.className = "stat-val";
      elements.threatScore.className = "stat-val";
    } else {
      elements.siteStatus.className = "stat-val safe-site";
      elements.threatScore.className = "stat-val safe-site";
    }
  }

  // Initial Boot
  initParticles();

  function withActiveHostname(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const hostname = normalizeHostname(tabs[0]?.url || "");
      if (!hostname) {
        setFeedback("The current tab does not expose a normal web domain.", "error");
        return;
      }
      callback(hostname);
    });
  }

  function normalizeHostname(input) {
    const trimmed = (input || "").trim().toLowerCase();
    if (!trimmed) return "";

    try {
      if (trimmed.includes("://")) {
        return new URL(trimmed).hostname.toLowerCase();
      }
      return new URL(`https://${trimmed}`).hostname.toLowerCase();
    } catch (error) {
      return "";
    }
  }

  function dedupeList(list) {
    return [...new Set(list.filter(Boolean))];
  }

  function setFeedback(message, type = "") {
    elements.feedback.textContent = message;
    elements.feedback.className = `feedback ${type}`.trim();
  }
  // --- UI Synchronizer (Hardware Shortcut Support) ---
  // If you use the keyboard shortcut (Alt+Shift+S) to toggle the shield,
  // this listener ensures the side-panel switch flips automatically.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.isScanningEnabled) {
      const isEnabled = changes.isScanningEnabled.newValue !== false;
      elements.scanToggle.checked = isEnabled;
      syncWithActiveTab();
      
      // Auto-close if disabled via hotkey
      if (!isEnabled) {
        setTimeout(() => window.close(), 400);
      }
    }
  });
});
