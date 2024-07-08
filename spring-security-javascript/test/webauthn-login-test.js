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
import { setup } from "../lib/webauthn-login.js";
import webauthn from "../lib/webauthn-core.js";
import { fake, stub } from "sinon";

describe("webauthn-login", () => {
  describe("bootstrap", () => {
    let authenticateStub;
    let isConditionalMediationAvailableStub;

    beforeEach(() => {
      isConditionalMediationAvailableStub = stub(
        webauthn,
        "isConditionalMediationAvailable",
      ).resolves(false);
      authenticateStub = stub(webauthn, "authenticate").resolves(undefined);
    });

    afterEach(() => {
      authenticateStub.restore();
      isConditionalMediationAvailableStub.restore();
    });

    it("sets up a click event listener on the signin button", async () => {
      const signinButton = {
        addEventListener: fake(),
      };

      await setup({}, "/some/path", signinButton);

      expect(signinButton.addEventListener.calledOnce).to.be.true;
      expect(signinButton.addEventListener.firstCall.firstArg).to.equal(
        "click",
      );
      expect(signinButton.addEventListener.firstCall.lastArg).to.be.a(
        "Function",
      );
    });

    it("calls authenticate when the signin button is clicked", async () => {
      const signinButton = {
        addEventListener: fake(),
      };
      const headers = { "x-header": "value" };
      const contextPath = "/some/path";

      await setup(headers, contextPath, signinButton);

      // Call the event listener
      await signinButton.addEventListener.firstCall.lastArg();

      expect(authenticateStub.calledOnce).to.be.true;
      expect(authenticateStub.firstCall.args).to.have.same.members([
        headers,
        contextPath,
        false,
      ]);
    });

    it("uses conditional mediation when available", async () => {
      isConditionalMediationAvailableStub.resolves(true);

      const headers = { "x-header": "value" };
      const contextPath = "/some/path";
      const signinButton = {
        addEventListener: fake(),
      };

      await setup(headers, contextPath, signinButton);

      expect(authenticateStub.calledOnce).to.be.true;
      expect(authenticateStub.firstCall.args).to.have.same.members([
        headers,
        contextPath,
        true,
      ]);
    });
  });
});
