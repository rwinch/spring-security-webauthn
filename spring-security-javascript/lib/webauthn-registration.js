/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

import webauthn from "./webauthn-core.js";

function setVisibility(element, value) {
  if (!element) {
    return;
  }
  element.style.display = value ? "block" : "none";
}
function setError(msg) {
  const error = document.getElementById("error");
  if (!error) {
    return;
  }
  setVisibility(error, true);
  error.textContent = msg;
}

function resetPopups() {
  const success = document.getElementById("success");
  const error = document.getElementById("error");
  setVisibility(success, false);
  setVisibility(error, false);
  if (!!success) {
    success.textContent = "";
  }
  if (!!error) {
    error.textContent = "";
  }
}

export async function setupRegistration(headers, contextPath, registerButton) {
  // TODO: show success
  resetPopups();

  if (!window.PublicKeyCredential) {
    setError("WebAuthn is not supported");
    return;
  }

  registerButton.addEventListener("click", async () => {
    resetPopups();
    const label = document.getElementById("label").value;
    try {
      await webauthn.register(headers, contextPath, label);
    } catch (err) {
      setError(err.message);
    }
  });
}
