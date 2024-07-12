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
(() => {
  // lib/base64url.js
  var base64url_default = {
    encode: function(buffer) {
      const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
      return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    },
    decode: function(base64url) {
      const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
      const binStr = window.atob(base64);
      const bin = new Uint8Array(binStr.length);
      for (let i = 0; i < binStr.length; i++) {
        bin[i] = binStr.charCodeAt(i);
      }
      return bin.buffer;
    }
  };

  // lib/http.js
  async function post(url, headers, body) {
    const options = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers
      }
    };
    if (body) {
      options.body = JSON.stringify(body);
    }
    return fetch(url, options);
  }
  var http_default = { post };

  // lib/webauthn-core.js
  async function isConditionalMediationAvailable() {
    return !!(document.PublicKeyCredential && document.PublicKeyCredential.isConditionalMediationAvailable && await document.PublicKeyCredential.isConditionalMediationAvailable());
  }
  async function authenticate(headers, contextPath, useConditionalMediation) {
    const abortController = new AbortController();
    const options = await http_default.post(`${contextPath}/webauthn/authenticate/options`, headers).then((r) => r.json());
    const decodedOptions = { ...options, challenge: base64url_default.decode(options.challenge) };
    const credentialOptions = {
      publicKey: decodedOptions,
      signal: abortController.signal
    };
    if (useConditionalMediation) {
      credentialOptions.mediation = "conditional";
    }
    const cred = await navigator.credentials.get(credentialOptions);
    const { response, type: credType } = cred;
    let userHandle;
    if (response.userHandle) {
      userHandle = base64url_default.encode(response.userHandle);
    }
    const body = {
      id: cred.id,
      rawId: base64url_default.encode(cred.rawId),
      response: {
        authenticatorData: base64url_default.encode(response.authenticatorData),
        clientDataJSON: base64url_default.encode(response.clientDataJSON),
        signature: base64url_default.encode(response.signature),
        userHandle
      },
      credType,
      clientExtensionResults: cred.getClientExtensionResults(),
      authenticatorAttachment: cred.authenticatorAttachment
    };
    const authenticationResponse = await http_default.post(`${contextPath}/login/webauthn`, headers, body).then((response2) => {
      if (response2.ok) {
        return response2.json();
      } else {
        return { errorUrl: "/login?error" };
      }
    });
    if (authenticationResponse && authenticationResponse.authenticated) {
      window.location.href = authenticationResponse.redirectUrl;
    } else {
      window.location.href = authenticationResponse.errorUrl;
    }
  }
  async function register(headers, contextPath, label) {
    if (!label) {
      throw new Error("Error: Passkey Label is required");
    }
    const optionsResponse = await http_default.post(`${contextPath}/webauthn/register/options`, headers);
    const options = await optionsResponse.json();
    let decodedExcludeCredentials = !options.excludeCredentials ? [] : options.excludeCredentials.map((cred) => ({
      ...cred,
      id: base64url_default.decode(cred.id)
    }));
    const decodedOptions = {
      ...options,
      user: {
        ...options.user,
        id: base64url_default.decode(options.user.id)
      },
      challenge: base64url_default.decode(options.challenge),
      excludeCredentials: decodedExcludeCredentials
    };
    const credentialsContainer = await navigator.credentials.create({
      publicKey: decodedOptions
    }).catch((e) => {
      throw new Error("Registration failed: " + e.message, { cause: e });
    });
    const { response } = credentialsContainer;
    const credential = {
      id: credentialsContainer.id,
      rawId: base64url_default.encode(credentialsContainer.rawId),
      response: {
        attestationObject: base64url_default.encode(response.attestationObject),
        clientDataJSON: base64url_default.encode(response.clientDataJSON),
        transports: response.getTransports ? response.getTransports() : [],
        publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        publicKey: base64url_default.encode(response.getPublicKey()),
        authenticatorData: base64url_default.encode(response.getAuthenticatorData())
      },
      type: credentialsContainer.type,
      clientExtensionResults: credentialsContainer.getClientExtensionResults(),
      authenticatorAttachment: credentialsContainer.authenticatorAttachment
    };
    const registrationRequest = {
      publicKey: {
        credential,
        label
      }
    };
    const verificationResp = await http_default.post(`${contextPath}/webauthn/register`, headers, registrationRequest);
    const verificationJSON = await verificationResp.json();
    if (verificationJSON && verificationJSON.success) {
      window.location.href = `${contextPath}/webauthn/register?success`;
    } else {
      throw new Error(`Registration failed! Response: <pre>${JSON.stringify(verificationJSON, null, 2)}</pre>`);
    }
  }
  var webauthn_core_default = {
    authenticate,
    register,
    isConditionalMediationAvailable
  };

  // lib/webauthn-login.js
  async function conditionalMediation(headers, contextPath) {
    const available = await webauthn_core_default.isConditionalMediationAvailable();
    if (available) {
      await webauthn_core_default.authenticate(headers, contextPath, true);
    }
    return available;
  }
  async function setupLogin(headers, contextPath, signinButton) {
    await conditionalMediation(headers, contextPath);
    signinButton.addEventListener("click", async () => {
      await webauthn_core_default.authenticate(headers, contextPath, false);
    });
  }

  // lib/webauthn-registration.js
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
  async function setupRegistration(headers, contextPath, registerButton) {
    resetPopups();
    if (!window.PublicKeyCredential) {
      setError("WebAuthn is not supported");
      return;
    }
    registerButton.addEventListener("click", async () => {
      resetPopups();
      const label = document.getElementById("label").value;
      try {
        await webauthn_core_default.register(headers, contextPath, label);
      } catch (err) {
        setError(err.message);
      }
    });
  }

  // lib/index.js
  window.setupLogin = setupLogin;
  window.setupRegistration = setupRegistration;
})();
