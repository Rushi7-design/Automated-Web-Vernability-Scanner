// background.js
// AWVS Background Service Worker for fully automated local scanning.

const AWVS_SERVER = "http://127.0.0.1:5000";
const API_KEY = "awvs_secret_api_key_2026";
const THROTTLE_MS = 5 * 60 * 1000; // 5 minutes throttle per URL

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only trigger on load completion to ensure we have the final URL
  if (changeInfo.status === "complete" && tab.url) {
    const url = tab.url;
    
    // Check if the target is a local address (e.g. localhost or 127.0.0.1)
    // We target local developments as they are primary candidates for auto-audit
    if (url.includes("localhost") || url.includes("127.0.0.1")) {
      // Avoid scanning the scanner dashboard itself
      if (url.startsWith(AWVS_SERVER)) {
        return;
      }

      const cleanUrl = url.split("?")[0].split("#")[0]; // Strip queries

      // Retrieve scan history to prevent double scans
      chrome.storage.local.get(["scanHistory"], (data) => {
        let history = data.scanHistory || {};
        const lastScanTime = history[cleanUrl] || 0;
        const now = Date.now();

        if (now - lastScanTime > THROTTLE_MS) {
          // Log and save to history
          history[cleanUrl] = now;
          chrome.storage.local.set({ scanHistory: history });

          console.log(`[AWVS] Fully automated scan triggered for local URL: ${cleanUrl}`);
          
          // Send request to API
          fetch(`${AWVS_SERVER}/api/v1/auto-scan`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-API-Key": API_KEY
            },
            body: JSON.stringify({
              target_url: cleanUrl,
              profile: "full"
            })
          })
          .then(res => res.json())
          .then(result => {
            if (result.ok) {
              // Trigger Chrome Toast Notification
              chrome.notifications.create({
                type: "basic",
                iconUrl: "icon.png", // fallback or default browser icon
                title: "🤖 AWVS Autonomous Audit",
                message: `Auto-scan successfully launched for: ${cleanUrl}`,
                priority: 1
              });
            }
          })
          .catch(err => {
            console.error("[AWVS] Auto-scan API trigger failed:", err);
          });
        }
      });
    }
  }
});
