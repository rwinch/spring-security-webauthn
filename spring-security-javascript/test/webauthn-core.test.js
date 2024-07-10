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
import { fake, assert } from "sinon";
import webauthn from "../lib/webauthn-core.js";

describe("webauthn-core", () => {
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
});
