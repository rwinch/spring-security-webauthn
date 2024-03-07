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

package org.springframework.security.web.webauthn.registration;

import static org.junit.jupiter.api.Assertions.*;

class WebAuthnRegistrationFilterTests {

	String body = """
		{
		  "publicKey": {
			"credential": {
			  "id": "dYF7EGnRFFIXkpXi9XU2wg",
			  "rawId": "dYF7EGnRFFIXkpXi9XU2wg",
			  "response": {
				"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAALraVWanqkAfvZZFYZpVEg0AEHWBexBp0RRSF5KV4vV1NsKlAQIDJiABIVggQjmrekPGzyqtoKK9HPUH-8Z2FLpoqkklFpFPQVICQ3IiWCD6I9Jvmor685fOZOyGXqUd87tXfvJk8rxj9OhuZvUALA",
				"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSl9RTi10SFJYRWVKYjlNcUNrWmFPLUdOVmlibXpGVGVWMk43Z0ptQUdrQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				"transports": [
				  "internal",
				  "hybrid"
				],
				"publicKeyAlgorithm": -7,
				"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQjmrekPGzyqtoKK9HPUH-8Z2FLpoqkklFpFPQVICQ3L6I9Jvmor685fOZOyGXqUd87tXfvJk8rxj9OhuZvUALA",
				"authenticatorData": "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAALraVWanqkAfvZZFYZpVEg0AEHWBexBp0RRSF5KV4vV1NsKlAQIDJiABIVggQjmrekPGzyqtoKK9HPUH-8Z2FLpoqkklFpFPQVICQ3IiWCD6I9Jvmor685fOZOyGXqUd87tXfvJk8rxj9OhuZvUALA"
			  },
			  "type": "public-key",
			  "clientExtensionResults": {},
			  "authenticatorAttachment": "platform"
			},
			"label": "1password"
		  }
		}
	""";
}