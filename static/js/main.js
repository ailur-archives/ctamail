addEventListener("DOMContentLoaded", function () {
    if (getCookie("darkMode") === "true") {
        applyDarkMode();
    }

    if (document.getElementById("username")) {
        document.getElementById("username").innerText = localStorage.getItem("user")
    }

    if (document.getElementById("logout")) {
        document.getElementById("logout").innerText = "Currently logging out " + localStorage.getItem("user") + ", please be patient..."
        localStorage.removeItem("user")
        localStorage.removeItem("hash")
        setCookie("loggedin", "false", 1, "Strict")
        window.location.href = "/account"
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

function signup() {
    fetch("/api/signup", {
        method: "POST",
        body: JSON.stringify({
            captcha: document.getElementById("captcha").value,
            unique_token: document.getElementById("unique_token").value,
            username: document.getElementById("username").value,
            password: document.getElementById("password").value
        })
    })
        .then((response) => response)
        .then((response) => {
             async function doStuff() {
                 console.log(response.status)
                 if (response.status === 200) {
                     window.location.href = "/success"
                 } else if (response.status === 501) {
                     window.location.href = "/taken"
                 } else if (response.status === 400) {
                     window.location.href = "/badcaptcha"
                 } else if (response.status === 402) {
                     window.location.href = "/invaliduser"
                 } else if (response.status === 403) {
                     window.location.href = "/invalidtoken"
                 } else {
                     window.location.href = "/signuperror"
                 }
             }
             doStuff()
        })
}

function login() {
    let username = document.getElementById("username").value
    fetch("/api/login", {
        method: "POST",
        body: JSON.stringify({
            username: username,
            password: document.getElementById("password").value
        })
    })
        .then((response) => response)
        .then((response) => {
            async function doStuff() {
                console.log(response.status)
                if (response.status === 200) {
                    setCookie("loggedin", "true", 30, "Strict")
                    const data = await response.json();
                    localStorage.setItem("user", username)
                    localStorage.setItem("hash", data.password)
                    window.location.reload()
                } else if (response.status === 401) {
                    window.location.href = "/baduser"
                } else if (response.status === 403) {
                    window.location.href = "/badpassword"
                } else {
                    window.location.href = "/loginerror"
                }
            }
            doStuff()
        })
}

function deleteacct() {
    fetch("/api/deleteacct", {
        method: "POST",
        body: JSON.stringify({
            username: localStorage.getItem("user"),
            password: localStorage.getItem("hash")
        })
    })
        .then((response) => response)
        .then((response) => {
            async function doStuff() {
                console.log(response.status)
                if (response.status === 200) {
                    window.location.href = "/logout"
                } else if (response.status === 401) {
                    window.location.href = "/usererror"
                } else {
                    window.location.href = "/accounterror"
                }
            }
            doStuff()
        })
}

function changepass() {
    fetch("/api/changepass", {
        method: "POST",
        body: JSON.stringify({
            username: localStorage.getItem("user"),
            password: localStorage.getItem("hash"),
            newpass: document.getElementById("newpass").value
        })
    })
        .then((response) => response)
        .then((response) => {
            async function doStuff() {
                console.log(response.status)
                if (response.status === 200) {
                    const data = await response.json();
                    localStorage.setItem("hash", data.password)
                    window.location.href = "/account"
                } else if (response.status === 401) {
                    window.location.href = "/usererror"
                } else {
                    window.location.href = "/accounterror"
                }
            }
            doStuff()
        })
}