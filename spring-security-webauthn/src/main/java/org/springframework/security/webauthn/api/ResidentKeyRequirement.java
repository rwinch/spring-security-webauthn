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

package org.springframework.security.webauthn.api;

/**
 * The <a href="https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement">ResidentKeyRequirement</a> describes
 * the Relying Partys requirements for client-side discoverable credentials.
 * @since 6.4
 * @author Rob Winch
 */
public enum ResidentKeyRequirement {

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-discouraged">discouraged</a> requirement
	 * indicates that the Relying Party prefers creating a server-side credential, but will accept a client-side
	 * discoverable credential.
	 */
	DISCOURAGED("discouraged"),

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-preferred">preferred</a> requirement
	 * indicates that the Relying Party strongly prefers creating a client-side discoverable credential, but will accept
	 * a server-side credential.
	 */
	PREFERRED("preferred"),

	/**
	 * The <a href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-required">required</a> value
	 * indicates that the Relying Party requires a client-side discoverable credential.
	 */
	REQUIRED("required");

	private final String value;

	ResidentKeyRequirement(String value) {
		this.value = value;
	}

	/**
	 * Gets the value.
	 * @return the value
	 */
	public String getValue() {
		return this.value;
	}

}
