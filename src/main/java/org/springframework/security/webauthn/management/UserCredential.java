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

import java.time.Instant;
import java.util.List;

import org.springframework.security.webauthn.api.ArrayBuffer;
import org.springframework.security.webauthn.api.BufferSource;
import org.springframework.security.webauthn.api.AuthenticatorTransport;

public interface UserCredential {

	List<AuthenticatorTransport> getTransports();

	ArrayBuffer getCredentialId();

	BufferSource getUserEntityUserId();

	PublicKeyCose getPublicKeyCose();

	long getSignatureCount();

	OptionalBoolean getBackupEligible();

	OptionalBoolean getBackupState();

	String getLabel();

	Instant getLastUsed();

	Instant getCreated();

}
