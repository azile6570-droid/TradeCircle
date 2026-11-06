"use strict";

const form = document.querySelector("#resetPasswordForm");
const submit = document.querySelector("#resetPasswordSubmit");
const message = document.querySelector("#resetPasswordMessage");
const loginLink = document.querySelector("#resetPasswordLoginLink");
const resetToken = new URLSearchParams(window.location.search).get("token");

window.history.replaceState(null, "", window.location.pathname);

function showMessage(text, isError = false) {
  message.textContent = text;
  message.classList.toggle("auth-error", isError);
  message.hidden = false;
}

if (!resetToken || !/^[a-f0-9]{64}$/.test(resetToken)) {
  submit.disabled = true;
  showMessage("This password reset link is invalid. Request a new one.", true);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!resetToken) return;

  const values = new FormData(form);
  const password = values.get("password");
  if (password !== values.get("confirm_password")) {
    showMessage("The passwords do not match.", true);
    return;
  }

  submit.disabled = true;
  message.hidden = true;
  try {
    const response = await fetch("/api/auth/reset-password", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: resetToken, password })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    showMessage(result.message);
    form.hidden = true;
    loginLink.hidden = false;
  } catch (error) {
    showMessage(
      error instanceof TypeError
        ? "Cannot reach the TradeCircle server. Try again later."
        : error.message,
      true
    );
    submit.disabled = false;
  }
});
