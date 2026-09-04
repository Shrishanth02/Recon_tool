// Apply the saved theme before paint to avoid a flash. Default: light.
// Extracted from an inline <script> so the Content-Security-Policy can keep a
// strict `script-src 'self'` (no 'unsafe-inline'). Loaded render-blocking in
// <head>, so it still runs before first paint.
(function () {
  try {
    var t = localStorage.getItem("reconx.theme");
    document.documentElement.setAttribute("data-theme", t === "dark" ? "dark" : "light");
  } catch {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
