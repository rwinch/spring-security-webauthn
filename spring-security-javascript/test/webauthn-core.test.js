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
import { fake, match, stub, assert } from "sinon";
import http from "../lib/http.js";
import webauthn from "../lib/webauthn-core.js";
import base64url from "../lib/base64url.js";

describe("webauthn-core", () => {
  before(() => {
    global.window = {
      btoa: (str) => Buffer.from(str, "binary").toString("base64"),
      atob: (b64) => Buffer.from(b64, "base64").toString("binary"),
    };
  });

  after(() => {
    delete global.window;
  });

  describe("isConditionalMediationAvailable", () => {
    afterEach(() => {
      delete global.document;
    });

    it("is available", async () => {
      global.document = {
        PublicKeyCredential: {
          isConditionalMediationAvailable: fake.resolves(true),
        },
      };

      const result = await webauthn.isConditionalMediationAvailable();

      expect(result).to.be.true;
    });

    it("is not available", async () => {
      global.document = {};
      let result = await webauthn.isConditionalMediationAvailable();
      expect(result).to.be.false;

      global.document = {
        PublicKeyCredential: {},
      };
      result = await webauthn.isConditionalMediationAvailable();
      expect(result).to.be.false;

      global.document = {
        PublicKeyCredential: {
          isConditionalMediationAvailable: fake.resolves(false),
        },
      };
      result = await webauthn.isConditionalMediationAvailable();
      expect(result).to.be.false;
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
  });
});
