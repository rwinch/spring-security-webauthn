
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

public enum COSEAlgorithmIdentifier {
	EdDSA(-8),
	ES256(-7),
	ES384(-35),
	ES512(-36),
	RS256(-257),
	RS384(-258),
	RS512(-259),
	RS1(-65535);

	private final long value;

	COSEAlgorithmIdentifier(long value) {
		this.value = value;
	}

	public long getValue() {
		return this.value;
	}
}
