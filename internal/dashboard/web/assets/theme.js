// Apply the stored theme before the page renders (prevents dark-theme flash).
try {
  var t = localStorage.getItem("exw-theme");
  if (t === "dark" || t === "light") document.documentElement.setAttribute("data-theme", t);
} catch (e) {}
