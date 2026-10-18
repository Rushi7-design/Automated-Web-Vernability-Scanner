// popup.js
const API_KEY = "awvs_secret_api_key_2026";
const DEFAULT_SERVER = "http://127.0.0.1:5000";

const profileSelect = document.getElementById('scan-profile');
const customContainer = document.getElementById('custom-container');
const serverUrlInput = document.getElementById('server-url');

// Load stored settings on popup display
chrome.storage.local.get(["scannerServerUrl"], (data) => {
  if (data.scannerServerUrl) {
    serverUrlInput.value = data.scannerServerUrl;
  } else {
    serverUrlInput.value = DEFAULT_SERVER;
  }
});

// Save settings dynamically on change
serverUrlInput.addEventListener('change', () => {
  let val = serverUrlInput.value.trim();
  if (val.endsWith("/")) {
    val = val.slice(0, -1);
  }
  chrome.storage.local.set({ scannerServerUrl: val });
});

profileSelect.addEventListener('change', () => {
  if (profileSelect.value === 'custom') {
    customContainer.style.display = 'block';
  } else {
    customContainer.style.display = 'none';
  }
});

document.getElementById('scan-btn').addEventListener('click', () => {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = "⌛ Launching Audit...";

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) {
      _showError("No active tab detected.");
      return;
    }

    const activeTabUrl = tabs[0].url;
    if (!activeTabUrl.startsWith('http://') && !activeTabUrl.startsWith('https://')) {
      _showError("Cannot scan this page type (requires http or https).");
      return;
    }

    const profile = profileSelect.value;
    let payload = {
      target_url: activeTabUrl,
      profile: profile
    };

    if (profile === 'custom') {
      payload.check_xss = document.getElementById('check-xss').checked;
      payload.check_sqli = document.getElementById('check-sqli').checked;
      payload.check_csrf = document.getElementById('check-csrf').checked;
      payload.check_headers = document.getElementById('check-headers').checked;
      payload.check_redirect = document.getElementById('check-redirect').checked;
      payload.enable_recon = document.getElementById('check-recon').checked;
      payload.check_advanced = document.getElementById('check-advanced').checked;
      payload.max_depth = parseInt(document.getElementById('max-depth').value) || 3;
      payload.max_pages = parseInt(document.getElementById('max-pages').value) || 100;
      payload.timeout = parseInt(document.getElementById('timeout').value) || 10;
    }

    // Read current target server destination
    let serverTarget = serverUrlInput.value.trim() || DEFAULT_SERVER;
    if (serverTarget.endsWith("/")) {
      serverTarget = serverTarget.slice(0, -1);
    }

    // Call REST API
    fetch(`${serverTarget}/api/v1/auto-scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
      },
      body: JSON.stringify(payload)
    })
    .then(res => {
      if (!res.ok) {
        return res.json().then(err => { throw new Error(err.error || "Server error"); });
      }
      return res.json();
    })
    .then(data => {
      if (data.ok && data.redirect_url) {
        btn.textContent = "✅ Success!";
        // Redirect and open scan page
        chrome.tabs.create({ url: data.redirect_url });
        setTimeout(() => { window.close(); }, 1000);
      } else {
        throw new Error("Invalid server response");
      }
    })
    .catch(err => {
      _showError(err.message);
    });
  });
});

function _showError(msg) {
  const btn = document.getElementById('scan-btn');
  btn.disabled = false;
  btn.textContent = "🚀 Start Vulnerability Scan";
  alert(`❌ Error: ${msg}`);
}
