"use strict";

const form = document.querySelector("#forgotPasswordForm");
const submit = document.querySelector("#forgotPasswordSubmit");
const message = document.querySelector("#forgotPasswordMessage");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = new FormData(form).get("email");
  submit.disabled = true;
  message.hidden = true;
  message.classList.remove("auth-error");

  try {
    const response = await fetch("/api/auth/forgot-password", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    message.textContent = result.message;
    message.hidden = false;
  } catch (error) {
    message.textContent = error instanceof TypeError
      ? "Cannot reach the TradeCircle server. Try again later."
      : error.message;
    message.classList.add("auth-error");
    message.hidden = false;
  } finally {
    submit.disabled = false;
  }
});
