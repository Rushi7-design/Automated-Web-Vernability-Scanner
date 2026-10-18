/* ============================================================
   AWVS v2.0 — Industry-Grade Frontend JavaScript
   ============================================================ */

(function () {
  'use strict';

  // ── FLASH MESSAGES AUTO-DISMISS ──────────────────────────────────────────
  document.querySelectorAll('.flash-msg').forEach(msg => {
    msg.addEventListener('click', () => msg.remove());
    setTimeout(() => {
      msg.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
      msg.style.opacity = '0';
      msg.style.transform = 'translateX(40px)';
      setTimeout(() => msg.remove(), 400);
    }, 5000);
  });

  // ── MOBILE SIDEBAR TOGGLE ─────────────────────────────────────────────────
  const menuToggle = document.getElementById('menu-toggle');
  const sidebar    = document.querySelector('.sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    document.addEventListener('click', e => {
      if (!sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });
  }

  // ── VULNERABILITY CARD ACCORDION ─────────────────────────────────────────
  document.querySelectorAll('.vuln-header').forEach(header => {
    header.addEventListener('click', e => {
      if (e.target.closest('button, a, form, select, input')) return;
      const card = header.closest('.vuln-card');
      const isOpen = card.classList.contains('open');
      // Close all others
      document.querySelectorAll('.vuln-card.open').forEach(c => c.classList.remove('open'));
      if (!isOpen) card.classList.add('open');
    });
  });

  // ── AUTO-EXPAND FIRST CRITICAL/HIGH FINDING ───────────────────────────────
  const firstHigh = document.querySelector('.vuln-card.critical, .vuln-card.high');
  if (firstHigh) firstHigh.classList.add('open');

  // ── SCAN PROFILE SELECTOR ─────────────────────────────────────────────────
  const PROFILES = {
    quick: {
      max_depth: '1', max_pages: '25', timeout: '5',
      modules: ['check_headers', 'enable_recon']
    },
    standard: {
      max_depth: '3', max_pages: '100', timeout: '10',
      modules: ['check_xss', 'check_sqli', 'check_csrf', 'check_headers', 'check_redirect', 'enable_recon']
    },
    full: {
      max_depth: '5', max_pages: '200', timeout: '20',
      modules: ['check_xss', 'check_sqli', 'check_csrf', 'check_headers', 'check_redirect', 'enable_recon', 'check_advanced']
    },
    custom: null,
  };

  const ALL_MODULES = ['check_xss', 'check_sqli', 'check_csrf', 'check_headers', 'check_redirect', 'enable_recon', 'check_advanced'];

  document.querySelectorAll('.profile-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.profile-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');

      const profile = PROFILES[card.dataset.profile];
      if (!profile) return; // custom — let user configure manually

      // Update selects
      ['max_depth', 'max_pages', 'timeout'].forEach(field => {
        const el = document.getElementById(field);
        if (el) el.value = profile[field];
      });

      // Update checkboxes
      ALL_MODULES.forEach(mod => {
        const el = document.querySelector(`input[name="${mod}"]`);
        if (el) el.checked = profile.modules.includes(mod);
      });
    });
  });

  // ── AUTO-FILL SCOPE FROM URL ───────────────────────────────────────────────
  const targetInput = document.getElementById('target_url');
  const scopeInput  = document.getElementById('scope');
  if (targetInput && scopeInput) {
    targetInput.addEventListener('input', function () {
      try {
        const val = this.value.trim();
        const url = new URL(val.startsWith('http') ? val : 'https://' + val);
        scopeInput.value = url.hostname;
      } catch (e) {}
    });
  }

  // ── SCAN FORM SUBMIT ANIMATION ────────────────────────────────────────────
  const scanForm = document.getElementById('scan-form');
  if (scanForm) {
    scanForm.addEventListener('submit', function () {
      const btn = document.getElementById('submit-btn');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spin">⚙️</span> Launching Scan…';
      }
    });
  }

  // ── TOPBAR LIVE CLOCK ─────────────────────────────────────────────────────
  const clockEl = document.getElementById('topbar-clock');
  if (clockEl) {
    const tick = () => {
      const now = new Date();
      clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    };
    tick();
    setInterval(tick, 1000);
  }

  // ── TABLE SEARCH FILTER ───────────────────────────────────────────────────
  const searchInput = document.getElementById('table-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const query = searchInput.value.toLowerCase();
      document.querySelectorAll('tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
      });
    });
  }

  // ── COPY TO CLIPBOARD ─────────────────────────────────────────────────────
  document.querySelectorAll('[data-copy]').forEach(el => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', () => {
      navigator.clipboard.writeText(el.dataset.copy).then(() => {
        const original = el.textContent;
        el.textContent = '✓ Copied!';
        setTimeout(() => el.textContent = original, 1800);
      }).catch(() => {});
    });
  });

  // ── PASSWORD STRENGTH METER ───────────────────────────────────────────────
  const pwInput  = document.getElementById('password');
  const pwMeter  = document.getElementById('pw-strength');
  if (pwInput && pwMeter) {
    pwInput.addEventListener('input', () => {
      const val = pwInput.value;
      let score = 0;
      if (val.length >= 8)  score++;
      if (/[A-Z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;
      const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
      const colors = ['', '#ef4444', '#f59e0b', '#3b82f6', '#10b981'];
      pwMeter.textContent = val.length ? labels[score] || 'Weak' : '';
      pwMeter.style.color = colors[score] || '#ef4444';
    });
  }

})();
