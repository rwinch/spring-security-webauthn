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

import { expect } from "chai";
import { assert, fake, match, stub } from "sinon";
import http from "../lib/http.js";
import webauthn from "../lib/webauthn-core.js";
import base64url from "../lib/base64url.js";

describe("webauthn-core", () => {
  beforeEach(() => {
    global.window = {
      btoa: (str) => Buffer.from(str, "binary").toString("base64"),
      atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    };
  });

  afterEach(() => {
    delete global.window;
  });

  describe("isConditionalMediationAvailable", () => {
    afterEach(() => {
      delete global.window.PublicKeyCredential;
    });

    it("is available", async () => {
      global.window = {
        PublicKeyCredential: {
          isConditionalMediationAvailable: fake.resolves(true),
        },
      };

      const result = await webauthn.isConditionalMediationAvailable();

      expect(result).to.be.true;
    });

    describe("is not available", async () => {
      it("PublicKeyCredential does not exist", async () => {
        global.window = {};
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
      it("PublicKeyCredential.isConditionalMediationAvailable undefined", async () => {
        global.window = {
          PublicKeyCredential: {},
        };
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
      it("PublicKeyCredential.isConditionalMediationAvailable false", async () => {
        global.window = {
          PublicKeyCredential: {
            isConditionalMediationAvailable: fake.resolves(false),
          },
        };
        const result = await webauthn.isConditionalMediationAvailable();
        expect(result).to.be.false;
      });
    });
  });

  describe("authenticate", () => {
    let httpPostStub;
    const contextPath = "/some/path";

    const credentialsGetOptions = {
      challenge: "nRbOrtNKTfJ1JaxfUDKs8j3B-JFqyGQw8DO4u6eV3JA",
      timeout: 300000,
      rpId: "localhost",
      allowCredentials: [],
      userVerification: "preferred",
      extensions: {},
    };

    // This is kind of a self-fulfilling prophecy type of test ; we produce array buffers by calling
    // base64url.decode ; they will then be re-encoded to the same string.
    // The ArrayBuffer API is not super friendly.
    beforeEach(() => {
      httpPostStub = stub(http, "post");
      httpPostStub.withArgs(contextPath + "/webauthn/authenticate/options", match.any).resolves({
        json: fake.resolves(credentialsGetOptions),
      });
      global.window = {
        ...global.window,
        location: {},
      };
      const validAuthenticatorResponse = {
        id: "UgghgP5QKozwsSUK1twCj8mpgZs",
        rawId: base64url.decode("UgghgP5QKozwsSUK1twCj8mpgZs"),
        response: {
          authenticatorData: base64url.decode("y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA"),
          clientDataJSON: base64url.decode(
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUTdlR0NkNUw2cG9fa01meWNIQnBWRlR5dmd3RklCV0QxZWg5OUktRFhnWSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
          ),
          signature: base64url.decode(
            "MEUCIGT9PAWfU3lMicOXFMpHGcl033dY-sNSJvehlXvvoivyAiEA_D_yOsChERlXX2rFcK6Qx5BaAbx5qdU2hgYDVN6W770",
          ),
          userHandle: base64url.decode("tyRDnKxdj7uWOT5jrchXu54lo6nf3bWOUvMQnGOXk7g"),
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: "platform",
        type: "public-key",
      };
      global.navigator = {
        credentials: {
          get: fake.resolves(validAuthenticatorResponse),
        },
      };
    });

    afterEach(() => {
      http.post.restore();
      delete global.navigator;
      delete global.window.location;
    });

    it("succeeds", async () => {
      httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
        ok: true,
        json: fake.resolves({
          authenticated: true,
          redirectUrl: "/success",
        }),
      });

      await webauthn.authenticate({ "x-custom": "some-value" }, contextPath, false);

      // TODO: assert options
      expect(global.window.location.href).to.equal("/success");
      assert.calledWith(
        httpPostStub.lastCall,
        `${contextPath}/login/webauthn`,
        { "x-custom": "some-value" },
        {
          id: "UgghgP5QKozwsSUK1twCj8mpgZs",
          rawId: "UgghgP5QKozwsSUK1twCj8mpgZs",
          credType: "public-key",
          response: {
            authenticatorData: "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA",
            clientDataJSON:
              "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUTdlR0NkNUw2cG9fa01meWNIQnBWRlR5dmd3RklCV0QxZWg5OUktRFhnWSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
            signature:
              "MEUCIGT9PAWfU3lMicOXFMpHGcl033dY-sNSJvehlXvvoivyAiEA_D_yOsChERlXX2rFcK6Qx5BaAbx5qdU2hgYDVN6W770",
            userHandle: "tyRDnKxdj7uWOT5jrchXu54lo6nf3bWOUvMQnGOXk7g",
          },
          clientExtensionResults: {},
          authenticatorAttachment: "platform",
        },
      );
    });

    it("is rejected by the server", async () => {
      httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).resolves({
        ok: false,
      });

      await webauthn.authenticate({}, contextPath, false);

      expect(global.window.location.href).to.equal("/login?error");
    });

    it("request fails", async () => {
      httpPostStub.withArgs(`${contextPath}/login/webauthn`, match.any, match.any).rejects("Server threw an error");

      try {
        await webauthn.authenticate({}, contextPath, false);
      } catch (err) {
        expect(err).to.be.an("error");
      }
    });
  });

  describe("register", () => {
    let httpPostStub;
    const contextPath = "/some/path";

    beforeEach(() => {
      const credentialsCreateOptions = {
        rp: { name: "Spring Security Relying Party", id: "example.localhost" },
        user: { name: "user", id: "eatPy60xmXG_58JrIiIBa5wq8Y76c7MD6mnY5vW8yP8", displayName: "user" },
        challenge: "s0hBOfkSaVLXdsbyD8jii6t2IjUd-eiTP1Cmeuo1qUo",
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        timeout: 300000,
        excludeCredentials: [
          {
            id: "nOsjw8eaaqSwVdTBBYE1FqfGdHs",
            type: "public-key",
            transports: [],
          },
        ],
        authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        attestation: "direct",
        extensions: { credProps: true },
      };
      const validAuthenticatorResponse = {
        authenticatorAttachment: "platform",
        id: "9wAuex_025BgEQrs7fOypo5SGBA",
        rawId: base64url.decode("9wAuex_025BgEQrs7fOypo5SGBA"),
        response: {
          attestationObject: base64url.decode(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
          ),
          getAuthenticatorData: () =>
            base64url.decode(
              "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
            ),
          clientDataJSON: base64url.decode(
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUVdwd3lUcXJpYVlqbVdnOWFvZ0FxUlRKNVFYMFBGV2JWR2xNeGNsVjZhcyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
          ),
          getPublicKey: () =>
            base64url.decode(
              "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwH2kzYF5J4Qbzd8AoVVIsoh-8MEFWjIaAyiIbET7paBrMCiMzmx25DLYzuvPV2jnmdVo0sZeHyTjEEfP47L3UQ",
            ),
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => ["internal"],
        },
        type: "public-key",
        getClientExtensionResults: () => ({}),
      };
      global.navigator = {
        credentials: {
          create: fake.resolves(validAuthenticatorResponse),
        },
      };
      httpPostStub = stub(http, "post");
      httpPostStub.withArgs(contextPath + "/webauthn/register/options", match.any).resolves({
        json: fake.resolves(credentialsCreateOptions),
      });
      httpPostStub.withArgs(`${contextPath}/webauthn/register`, match.any, match.any).resolves({
        ok: true,
        json: fake.resolves({
          success: true,
        }),
      });

      global.window = {
        ...global.window,
        location: {},
      };
    });

    afterEach(() => {
      httpPostStub.restore();
      delete global.navigator;
      delete global.window.location;
    });

    it("succeeds", async () => {
      const contextPath = "/some/path";
      const headers = { _csrf: "csrf-value" };

      await webauthn.register(headers, contextPath, "my passkey");
      assert.calledWithExactly(
        httpPostStub.lastCall,
        `${contextPath}/webauthn/register`,
        headers,
        match({
          publicKey: {
            credential: {
              id: "9wAuex_025BgEQrs7fOypo5SGBA",
              rawId: "9wAuex_025BgEQrs7fOypo5SGBA",
              response: {
                attestationObject:
                  "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAAPv8MAcVTk7MjAtuAgVX170AFPcALnsf9NuQYBEK7O3zsqaOUhgQpQECAyYgASFYIMB9pM2BeSeEG83fAKFVSLKIfvDBBVoyGgMoiGxE-6WgIlggazAojM5sduQy2M7rz1do55nVaNLGXh8k4xBHz-Oy91E",
                clientDataJSON:
                  "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUVdwd3lUcXJpYVlqbVdnOWFvZ0FxUlRKNVFYMFBGV2JWR2xNeGNsVjZhcyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyJ9",
                transports: ["internal"],
              },
              type: "public-key",
              clientExtensionResults: {},
              authenticatorAttachment: "platform",
            },
            label: "my passkey",
          },
        }),
      );
    });

    it("throws when label is missing", async () => {
      try {
        await webauthn.register({}, "/", "");
      } catch (err) {
        expect(err).to.be.an("error");
        return;
      }
      expect.fail("register should throw");
    });

    it("calls the authenticator with the correct options", async () => {
      await webauthn.register({}, contextPath, "my passkey");

      assert.calledOnceWithExactly(
        global.navigator.credentials.create,
        match({
          publicKey: {
            rp: {
              name: "Spring Security Relying Party",
              id: "example.localhost",
            },
            user: {
              name: "user",
              id: base64url.decode("eatPy60xmXG_58JrIiIBa5wq8Y76c7MD6mnY5vW8yP8"),
              displayName: "user",
            },
            challenge: base64url.decode("s0hBOfkSaVLXdsbyD8jii6t2IjUd-eiTP1Cmeuo1qUo"),
            pubKeyCredParams: [
              {
                type: "public-key",
                alg: -8,
              },
              {
                type: "public-key",
                alg: -7,
              },
              {
                type: "public-key",
                alg: -257,
              },
            ],
            timeout: 300000,
            excludeCredentials: [
              {
                id: base64url.decode("nOsjw8eaaqSwVdTBBYE1FqfGdHs"),
                type: "public-key",
                transports: [],
              },
            ],
            authenticatorSelection: {
              residentKey: "required",
              userVerification: "preferred",
            },
            attestation: "direct",
            extensions: { credProps: true },
          },
          signal: match.any,
        }),
      );
    });

    it("throws when the navigator.credentials.create fails", async () => {
      global.navigator = {
        credentials: {
          create: fake.rejects("authenticator threw an error"),
        },
      };
      try {
        await webauthn.register({}, contextPath, "my passkey");
      } catch (err) {
        expect(err).to.be.an("error");
        expect(err.message).to.equal("Registration failed: authenticator threw an error");
        expect(err.cause).to.deep.equal(new Error("authenticator threw an error"));
        return;
      }
      expect.fail("register should throw");
    });

    it("throws when the registration fails", () => {
      // TODO
    });
  });
});
