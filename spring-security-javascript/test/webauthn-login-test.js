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

/* eslint-env mocha */
"use strict";

import { expect } from "chai";
import { setup } from "../lib/webauthn-login.js";

describe("webauthn-login", () => {
  describe("bootstrap", () => {
    it("should be able to require extension", () => {
      expect(setup).to.be.instanceOf(Function);
    });
  });
});
