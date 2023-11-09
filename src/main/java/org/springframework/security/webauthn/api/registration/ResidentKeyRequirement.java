
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

package org.springframework.security.webauthn.api.registration;

public enum ResidentKeyRequirement {

	/**
	 * The client and authenticator will try to create a server-side credential if possible, and a
	 * discoverable credential (passkey) otherwise.
	 *
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
	 * Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
	 * discoverable Credential</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
	 * Credential</a>
	 * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a> in <a
	 * href="https://passkeys.dev">passkeys.dev</a> reference
	 */
	DISCOURAGED("discouraged"),

	/**
	 * The client and authenticator will try to create a discoverable credential (passkey) if
	 * possible, and a server-side credential otherwise.
	 *
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
	 * Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
	 * discoverable Credential</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
	 * Credential</a>
	 * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a> in <a
	 * href="https://passkeys.dev">passkeys.dev</a> reference
	 */
	PREFERRED("preferred"),

	/**
	 * The client and authenticator will try to create a discoverable credential (passkey), and fail
	 * the registration if that is not possible.
	 *
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
	 * Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
	 * discoverable Credential</a>
	 * @see <a
	 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
	 * Credential</a>
	 * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a> in <a
	 * href="https://passkeys.dev">passkeys.dev</a> reference
	 */
	REQUIRED("required");

	private final String value;

	ResidentKeyRequirement(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}