const loginView = document.getElementById("loginView");
const signupView = document.getElementById("signupView");
const showLoginBtn = document.getElementById("showLoginBtn");
const showSignupBtn = document.getElementById("showSignupBtn");
const goSignup = document.getElementById("goSignup");
const goLogin = document.getElementById("goLogin");

const loginForm = document.getElementById("loginForm");
const signupForm = document.getElementById("signupForm");

const loginMessage = document.getElementById("loginMessage");
const signupMessage = document.getElementById("signupMessage");

const signupPassword = document.getElementById("signupPassword");
const strengthLabel = document.getElementById("strengthLabel");
const strengthBars = document.querySelectorAll(".pg-strength-bars span");
const signupBtn = document.getElementById("signupBtn");
const termsCheck = document.getElementById("termsCheck");
const forgotPasswordBtn = document.getElementById("forgotPasswordBtn");

let recaptchaVerified = false;
let recaptchaToken = "";

function setView(view) {
  const isLogin = view === "login";
  loginView.classList.toggle("active", isLogin);
  signupView.classList.toggle("active", !isLogin);
  showLoginBtn.classList.toggle("active", isLogin);
  showSignupBtn.classList.toggle("active", !isLogin);
  clearMessages();
}

showLoginBtn?.addEventListener("click", () => setView("login"));
showSignupBtn?.addEventListener("click", () => setView("signup"));
goSignup?.addEventListener("click", () => setView("signup"));
goLogin?.addEventListener("click", () => setView("login"));

document.querySelectorAll("[data-toggle]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = document.querySelector(btn.getAttribute("data-toggle"));
    if (!target) return;
    const hidden = target.type === "password";
    target.type = hidden ? "text" : "password";
    btn.textContent = hidden ? "Hide" : "Show";
  });
});

function setError(id, message = "") {
  const el = document.getElementById(id);
  if (el) el.textContent = message;
}

function clearMessages() {
  [loginMessage, signupMessage].forEach((el) => {
    if (!el) return;
    el.className = "pg-message hidden";
    el.textContent = "";
  });
}

function setMessage(el, type, text) {
  if (!el) return;
  el.className = `pg-message ${type}`;
  el.textContent = text;
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getPasswordScore(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  return score;
}

function updateStrength(password) {
  const score = getPasswordScore(password);
  const labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"];
  strengthLabel.textContent = labels[score] || "Very weak";

  strengthBars.forEach((bar, index) => {
    bar.classList.toggle("active", index <= score - 1);
  });
}

signupPassword?.addEventListener("input", (e) => updateStrength(e.target.value));

function canSubmitSignup() {
  return recaptchaVerified && !!termsCheck?.checked;
}

function refreshSignupButton() {
  if (!signupBtn) return;
  signupBtn.disabled = !canSubmitSignup();
}

termsCheck?.addEventListener("change", refreshSignupButton);

window.onRecaptchaSuccess = function (token) {
  recaptchaVerified = true;
  recaptchaToken = token || "";
  setError("captchaError", "");
  refreshSignupButton();
};

window.onRecaptchaExpired = function () {
  recaptchaVerified = false;
  recaptchaToken = "";
  setError("captchaError", "Human verification expired. Please verify again.");
  refreshSignupButton();
};

function setLoading(button, loading) {
  if (!button) return;
  const text = button.querySelector(".pg-btn-text");
  const spinner = button.querySelector(".pg-spinner");

  if (text && loading) {
    text.dataset.original = text.textContent;
    text.textContent = "Please wait...";
  } else if (text && !loading) {
    text.textContent = text.dataset.original || text.textContent;
  }

  if (spinner) {
    spinner.classList.toggle("hidden", !loading);
  }

  if (button === signupBtn) {
    button.disabled = loading || !canSubmitSignup();
  } else {
    button.disabled = loading;
  }
}

loginForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMessages();

  setError("loginEmailError", "");
  setError("loginPasswordError", "");

  const email = document.getElementById("loginEmail")?.value.trim() || "";
  const password = document.getElementById("loginPassword")?.value.trim() || "";

  let hasError = false;

  if (!email) {
    setError("loginEmailError", "Email is required.");
    hasError = true;
  } else if (!validateEmail(email)) {
    setError("loginEmailError", "Enter a valid email address.");
    hasError = true;
  }

  if (!password) {
    setError("loginPasswordError", "Password is required.");
    hasError = true;
  }

  if (hasError) return;

  const btn = document.getElementById("loginBtn");
  setLoading(btn, true);

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        name: email,
        password
      })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.ok) {
      setMessage(loginMessage, "error", data.error || "Login failed.");
      return;
    }

    setMessage(loginMessage, "success", data.message || "Login successful.");

    setTimeout(() => {
      window.location.href = data.redirect_url || "/tool/dashboard";
    }, 900);
  } catch (err) {
    setMessage(loginMessage, "error", "Login failed. Please try again.");
  } finally {
    setLoading(btn, false);
  }
});

signupForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMessages();

  setError("signupNameError", "");
  setError("signupEmailError", "");
  setError("signupPasswordError", "");
  setError("signupConfirmPasswordError", "");
  setError("captchaError", "");
  setError("termsError", "");

  const full_name = document.getElementById("signupName")?.value.trim() || "";
  const email = document.getElementById("signupEmail")?.value.trim() || "";
  const password = document.getElementById("signupPassword")?.value || "";
  const confirm_password = document.getElementById("signupConfirmPassword")?.value || "";
  const accept_terms = !!termsCheck?.checked;

  let hasError = false;

  if (!full_name) {
    setError("signupNameError", "Full name is required.");
    hasError = true;
  }

  if (!email) {
    setError("signupEmailError", "Email is required.");
    hasError = true;
  } else if (!validateEmail(email)) {
    setError("signupEmailError", "Enter a valid email address.");
    hasError = true;
  }

  if (!password) {
    setError("signupPasswordError", "Password is required.");
    hasError = true;
  } else if (password.length < 8) {
    setError("signupPasswordError", "Password must be at least 8 characters.");
    hasError = true;
  }

  if (!confirm_password) {
    setError("signupConfirmPasswordError", "Confirm your password.");
    hasError = true;
  } else if (confirm_password !== password) {
    setError("signupConfirmPasswordError", "Passwords do not match.");
    hasError = true;
  }

  if (!recaptchaVerified || !recaptchaToken) {
    setError("captchaError", "Complete human verification.");
    hasError = true;
  }

  if (!accept_terms) {
    setError("termsError", "You must accept the Terms of Service and Privacy Policy.");
    hasError = true;
  }

  if (hasError) return;

  setLoading(signupBtn, true);

  try {
    const res = await fetch("/api/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        full_name,
        email,
        password,
        confirm_password,
        accept_terms,
        recaptcha_token: recaptchaToken
      })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.ok) {
      if (data.errors) {
        if (data.errors.full_name) setError("signupNameError", data.errors.full_name);
        if (data.errors.email) setError("signupEmailError", data.errors.email);
        if (data.errors.password) setError("signupPasswordError", data.errors.password);
        if (data.errors.confirm_password) setError("signupConfirmPasswordError", data.errors.confirm_password);
        if (data.errors.captcha) setError("captchaError", data.errors.captcha);
        if (data.errors.accept_terms) setError("termsError", data.errors.accept_terms);
      }

      setMessage(signupMessage, "error", data.error || "Signup failed.");
      return;
    }

    setMessage(signupMessage, "success", data.message || "Account created successfully.");

    signupForm.reset();
    updateStrength("");
    recaptchaVerified = false;
    recaptchaToken = "";
    refreshSignupButton();

    if (window.grecaptcha) {
      try {
        grecaptcha.reset();
      } catch (e) {}
    }

    setTimeout(() => {
      setView("login");
    }, 1200);
  } catch (err) {
    setMessage(signupMessage, "error", "Signup failed. Please try again.");
  } finally {
    setLoading(signupBtn, false);
    refreshSignupButton();
  }
});

forgotPasswordBtn?.addEventListener("click", async () => {
  clearMessages();

  const email = prompt("Enter your registered email");
  if (!email) return;

  try {
    const res = await fetch("/api/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.ok) {
      setMessage(loginMessage, "error", data.error || "Failed to process forgot password request.");
      return;
    }

    if (data.reset_token) {
      const token = prompt("Reset token generated. Paste it here:", data.reset_token);
      if (!token) {
        setMessage(loginMessage, "success", "Reset token generated.");
        return;
      }

      const newPassword = prompt("Enter your new password");
      if (!newPassword) return;

      const confirmPassword = prompt("Confirm your new password");
      if (!confirmPassword) return;

      const resetRes = await fetch("/api/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: token.trim(),
          new_password: newPassword,
          confirm_password: confirmPassword
        })
      });

      const resetData = await resetRes.json().catch(() => ({}));

      if (!resetRes.ok || !resetData.ok) {
        setMessage(loginMessage, "error", resetData.error || "Password reset failed.");
        return;
      }

      setMessage(loginMessage, "success", resetData.message || "Password reset successful.");
      return;
    }

    setMessage(loginMessage, "success", data.message || "Reset instructions generated.");
  } catch (err) {
    setMessage(loginMessage, "error", "Request failed. Please try again.");
  }
});

refreshSignupButton();
updateStrength("");