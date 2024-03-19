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


// FIXME: Verify packages of registration and authentication are correct
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.jackson.AttestationConveyancePreferenceSerializer;

public enum AttestationConveyancePreference {
	NONE("none"),
	INDIRECT("indirect"),
	DIRECT("direct"),
	ENTERPRISE("enterprise");

	private final String value;

	AttestationConveyancePreference(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}