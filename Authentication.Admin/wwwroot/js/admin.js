// Admin panel behaviour. Progressive enhancement only: every form works without this script,
// which just adds a confirm step before destructive actions and a small toggle on the setup
// form. No inline handlers, so it is compatible with a strict `script-src 'self'` CSP.
(function () {
    "use strict";

    // ---- Confirm before a destructive submit --------------------------------------------
    // Any <form data-confirm="Are you sure?"> asks before it posts.
    function wireConfirms() {
        document.querySelectorAll("form[data-confirm]").forEach(function (form) {
            form.addEventListener("submit", function (event) {
                var message = form.getAttribute("data-confirm");
                if (message && !window.confirm(message)) {
                    event.preventDefault();
                }
            });
        });
    }

    // ---- Setup form: hide the password when promoting an existing user ------------------
    function wirePromoteToggle() {
        var toggle = document.querySelector("[data-toggle-promote]");
        var passwordBlock = document.querySelector("[data-hide-when-promote]");
        if (!toggle || !passwordBlock) {
            return;
        }

        function sync() {
            passwordBlock.style.display = toggle.checked ? "none" : "";
        }

        toggle.addEventListener("change", sync);
        sync();
    }

    document.addEventListener("DOMContentLoaded", function () {
        wireConfirms();
        wirePromoteToggle();
    });
})();
