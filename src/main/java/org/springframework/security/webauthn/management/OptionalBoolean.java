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

// FIXME: Consider placing in a place that is reusable
public enum OptionalBoolean {
	TRUE(true),
	FALSE(false),
	UNKNOWN(null);

	private final Boolean value;

	OptionalBoolean(Boolean value) {
		this.value = value;
	}

	public Boolean getValue() {
		return this.value;
	}

	public static OptionalBoolean fromBoolean(Boolean value) {
		if (value == null) {
			return UNKNOWN;
		}
		return value ? TRUE : FALSE;
	}
}
