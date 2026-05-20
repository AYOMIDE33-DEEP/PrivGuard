(function () {
  const hostId = "pgToasts";
  const bootState = {
    crypto: false,
    gmail: false
  };

  function el(tag, cls) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    return e;
  }

  function debugLog(...args) {
    try {
      console.log("[PrivGuard UI]", ...args);
    } catch (_) {}
  }

  function debugError(...args) {
    try {
      console.error("[PrivGuard UI]", ...args);
    } catch (_) {}
  }

  window.pgToast = function (message, type = "info", ttl = 2600) {
    const host = document.getElementById(hostId);

    if (!host) {
      debugLog("Toast host missing:", message);
      return;
    }

    const t = el("div", "toastx " + type);
    const msg = el("div", "toastx-msg");
    msg.textContent = String(message || "");

    const x = el("button", "toastx-x");
    x.type = "button";
    x.textContent = "✕";
    x.onclick = () => {
      t.classList.add("out");
      setTimeout(() => t.remove(), 160);
    };

    t.appendChild(msg);
    t.appendChild(x);
    host.appendChild(t);

    requestAnimationFrame(() => t.classList.add("in"));

    setTimeout(() => {
      t.classList.add("out");
      setTimeout(() => t.remove(), 180);
    }, ttl);
  };

  function runInlineScripts(scope) {
    if (!scope) return;

    const scripts = scope.querySelectorAll("script:not([data-executed])");

    scripts.forEach((oldScript) => {
      try {
        const newScript = document.createElement("script");

        for (const attr of oldScript.attributes) {
          newScript.setAttribute(attr.name, attr.value);
        }

        newScript.setAttribute("data-executed", "1");
        newScript.textContent = oldScript.textContent || "";

        if (oldScript.parentNode) {
          oldScript.parentNode.replaceChild(newScript, oldScript);
        }
      } catch (err) {
        debugError("Inline script execution failed:", err);
      }
    });
  }

  function bootCrypto() {
    const cryptoRoot = document.querySelector(".crypto-card");
    if (!cryptoRoot) {
      bootState.crypto = false;
      return;
    }

    if (cryptoRoot.dataset.cryptoInit === "1") {
      bootState.crypto = true;
      return;
    }

    cryptoRoot.dataset.cryptoInit = "1";
    bootState.crypto = true;
    debugLog("Booting crypto UI");

    if (typeof window.cryptoResetAll === "function") {
      try {
        window.cryptoResetAll();
      } catch (err) {
        debugError("cryptoResetAll failed:", err);
        if (window.pgToast) window.pgToast("Crypto initialization failed", "error");
      }
    }
  }

  function bootGmail() {
    const gmailRoot = document.querySelector(".gmail-root");
    if (!gmailRoot) {
      bootState.gmail = false;
      return;
    }

    if (gmailRoot.dataset.gmailInit === "1") {
      bootState.gmail = true;
      return;
    }

    gmailRoot.dataset.gmailInit = "1";
    bootState.gmail = true;
    debugLog("Booting Gmail UI");

    // Gmail page already defines its own inline onclick handlers and action functions.
    // Do not bind Gmail action buttons here.
    // Only trigger initial page refresh if defined.
    if (typeof window.refreshAll === "function") {
      setTimeout(() => {
        try {
          debugLog("Calling Gmail refreshAll()");
          window.refreshAll();
        } catch (err) {
          debugError("refreshAll failed:", err);
          if (window.pgToast) window.pgToast("Gmail refresh failed", "error");
        }
      }, 250);
    } else {
      debugLog("window.refreshAll not found yet for Gmail");
    }
  }

  function bootAllTools() {
    bootCrypto();
    bootGmail();
  }

  function initDynamicToolScripts() {
    const gmailRoot = document.querySelector(".gmail-root");
    if (gmailRoot && gmailRoot.dataset.scriptsExecuted !== "1") {
      gmailRoot.dataset.scriptsExecuted = "1";
      debugLog("Executing dynamic Gmail scripts");
      runInlineScripts(gmailRoot.parentElement || gmailRoot);
    }

    const cryptoRoot = document.querySelector(".crypto-card");
    if (cryptoRoot && cryptoRoot.dataset.scriptsExecuted !== "1") {
      cryptoRoot.dataset.scriptsExecuted = "1";
      debugLog("Executing dynamic Crypto scripts");
      runInlineScripts(cryptoRoot.parentElement || cryptoRoot);
    }
  }

  function safeBoot() {
    try {
      initDynamicToolScripts();
      bootAllTools();
    } catch (err) {
      debugError("safeBoot failed:", err);
    }
  }

  document.addEventListener("DOMContentLoaded", safeBoot);
  window.addEventListener("load", safeBoot);

  setTimeout(safeBoot, 300);
  setTimeout(safeBoot, 800);
  setTimeout(safeBoot, 1500);

  const mo = new MutationObserver(() => {
    safeBoot();
  });

  if (document.documentElement) {
    mo.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }
})();