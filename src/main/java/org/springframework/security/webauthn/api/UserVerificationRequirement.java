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

package org.springframework.security.webauthn.api;

public enum UserVerificationRequirement {

	/**
	 * This value indicates that the Relying Party does not want user verification employed during the
	 * operation (e.g., in the interest of minimizing disruption to the user interaction flow).
	 */
	DISCOURAGED("discouraged"),

	/**
	 * This value indicates that the Relying Party prefers user verification for the operation if
	 * possible, but will not fail the operation if the response does not have the user verification flag set.
	 */
	PREFERRED("preferred"),

	/**
	 * Indicates that the Relying Party requires user verification for the operation and will fail the
	 * operation if the response does not have the user verification flag set.
	 */
	REQUIRED("required");

	private final String value;

	UserVerificationRequirement(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}