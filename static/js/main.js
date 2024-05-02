addEventListener("DOMContentLoaded", function () {
    if (getCookie("darkMode") === "true") {
        applyDarkMode();
    }
})

function toggleDarkMode() {
    if (getCookie("darkMode") === "true") {
        setCookie("darkMode", "false", 365, "Strict");
        applyLightMode();
    } else {
        setCookie("darkMode", "true", 365, "Strict");
        applyDarkMode();
    }
}


function applyDarkMode() {
    document.body.classList.add("darkmode");
}

function applyLightMode() {
    document.body.classList.remove("darkmode");
}

// Helper functions for handling cookies
function setCookie(name, value, days, sameSite) {
    let expires = "";
    let sameSiteAttribute = "";
    if (days) {
        let date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    if (sameSite) {
        sameSiteAttribute = "; samesite=" + sameSite;
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/" + sameSiteAttribute;
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}