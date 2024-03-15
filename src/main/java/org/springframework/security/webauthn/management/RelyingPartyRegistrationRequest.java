/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.util.Assert;

public class RelyingPartyRegistrationRequest {

	private final PublicKeyCredentialCreationOptions options;

	private final RelyingPartyPublicKey publicKey;


	public RelyingPartyRegistrationRequest(PublicKeyCredentialCreationOptions options, RelyingPartyPublicKey publicKey) {
		Assert.notNull(options, "options cannot be null");
		Assert.notNull(publicKey, "publicKey cannot be null");
		this.options = options;
		this.publicKey = publicKey;
	}

	public PublicKeyCredentialCreationOptions getCreationOptions() {
		return this.options;
	}

	public RelyingPartyPublicKey getPublicKey() {
		return this.publicKey;
	}
}
