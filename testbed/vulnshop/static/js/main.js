// VoltMart storefront — minimal cart interactivity (add-to-cart without a full reload).
(function () {
  "use strict";

  function updateBadge(count) {
    var badge = document.getElementById("cart-badge");
    if (badge) badge.textContent = count;
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-add]");
    if (!btn) return;
    e.preventDefault();
    var pid = btn.getAttribute("data-add");

    fetch("/cart/add/" + pid, {
      method: "POST",
      headers: { "X-Requested-With": "XMLHttpRequest" },
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data && data.count != null) updateBadge(data.count);
        var original = btn.textContent;
        btn.textContent = "✓ Added";
        btn.classList.add("added");
        setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("added");
        }, 1100);
      })
      .catch(function () {
        // Fall back to a normal navigation if the fetch fails.
        window.location.href = "/cart/add/" + pid;
      });
  });
})();
