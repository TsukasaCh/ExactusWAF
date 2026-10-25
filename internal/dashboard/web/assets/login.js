"use strict";
// Small login-page interactions: password toggle, Caps Lock, theme, loading.
(function () {
  var pw = document.getElementById("password");
  var eye = document.getElementById("eye");
  var caps = document.getElementById("caps");
  var form = document.getElementById("loginForm");
  var btn = document.getElementById("submit");
  var spin = document.getElementById("spin");
  var txt = document.getElementById("submitText");

  if (eye && pw) {
    eye.addEventListener("click", function () {
      var show = pw.type === "password";
      pw.type = show ? "text" : "password";
      eye.classList.toggle("on", show);
      eye.setAttribute("aria-pressed", String(show));
      eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
      pw.focus();
    });
  }

  function capsCheck(e) {
    if (!caps || !e.getModifierState) return;
    caps.hidden = !e.getModifierState("CapsLock");
  }
  if (pw) {
    pw.addEventListener("keydown", capsCheck);
    pw.addEventListener("keyup", capsCheck);
    pw.addEventListener("blur", function () { if (caps) caps.hidden = true; });
  }

  if (form) {
    form.addEventListener("submit", function () {
      if (btn) btn.disabled = true;
      if (spin) spin.hidden = false;
      if (txt) txt.textContent = "Checking…";
    });
  }
  // Restore the button if the user navigates back from a cached page.
  window.addEventListener("pageshow", function () {
    if (btn) btn.disabled = false;
    if (spin) spin.hidden = true;
    if (txt) txt.textContent = "Sign in";
  });

  // Theme toggle (stored in localStorage, same key as the console).
  var toggle = document.getElementById("themeToggle");
  function applyIcon() {
    var dark = document.documentElement.getAttribute("data-theme") === "dark";
    var moon = document.querySelector(".t-moon"), sun = document.querySelector(".t-sun");
    if (moon && sun) { moon.style.display = dark ? "none" : "block"; sun.style.display = dark ? "block" : "none"; }
  }
  applyIcon();
  if (toggle) {
    toggle.addEventListener("click", function () {
      var dark = document.documentElement.getAttribute("data-theme") === "dark";
      var next = dark ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("exw-theme", next); } catch (e) {}
      applyIcon();
    });
  }
})();
