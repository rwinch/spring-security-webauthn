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

package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.type.TypeReference;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Base64;

public class ResponseTests {
	@Test
	void go() throws Exception {
		String json = """
				"id": "vPpM1sscjOf6qnoFnmjr5A",
				      "rawId": "vPpM1sscjOf6qnoFnmjr5A",
				      "response": {
				        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUeIPs9X7OygKhjvhG6-chsNMkKJ0G-hi300N9f069vtJdAAAAALraVWanqkAfvZZFYZpVEg0AELz6TNbLHIzn-qp6BZ5o6-SlAQIDJiABIVggStKygu6CVB0aibcCzqcDp4xrevei9TZJ8m5WI9QMcXkiWCDdddI5XWSLBo8mYDbuWO5U523fuD8b7Vr5VuAdMHXKjQ",
				        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiejdxM0lOOHFyTG9WMDRFektPalpVMHgzWGhBLXNub001bHR1STdqX3ZvNCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0LmV4YW1wbGU6ODQ0MyJ9",
				        "transports": [
				          "internal",
				          "hybrid"
				        ]
				      },
				      "type": "public-key",
				      "clientExtensionResults": {},
				      "authenticatorAttachment": "platform"
				    }
				""";

		PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> result = JacksonCodecs.json().readValue(json, new TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>>() {
		});
		System.out.println(result);
	}

	@Test
	void runAttestationObject() throws Exception {
		String aO = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1MnZAnMmJxqJzlH8rzKO1nPxe-M0af-Xnoq43VAeZk9dAAAAALraVWanqkAfvZZFYZpVEg0AEFscJvQk-q6VM6_8CxB15kKlAQIDJiABIVgg9T394sj_4WqXaeFPe7TZVhzPvMjQLAguihfxx5Ucfe4iWCD4vwLnY-m6O-yfqN222ekP2CNtxcU6dCnOqFoimxM4bQ";

		attestationObject(aO);
	}


	@Test
	void runClientData() throws Exception {
		String base64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQURwMFdHajBBZFIyZzlUYmJDbzFjdUl1akszeF9uQU5yZEpURUlONkZjTS12TmRJeU9lQ3lNbmVWc0JKeVJleGxLWkZJTVJHQ3BJZEZsWDdVd0VYWEs2UXhtUzIzRFFabVEiLCJvcmlnaW4iOiJodHRwczovL215YWNjb3VudC5nb29nbGUuY29tIn0";

		clientData(base64);
	}

	@Test
	void another() throws Exception {
		String base64 = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVnBRMW5OQTl6OWgwb3R6VFcxQTlyLUJWSFk2NkVVMjFTQlpzV1k0d0huSSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0LmV4YW1wbGU6ODQ0MyJ9";
		clientData(base64);

		attestationObject("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUeIPs9X7OygKhjvhG6-chsNMkKJ0G-hi300N9f069vtJdAAAAALraVWanqkAfvZZFYZpVEg0AECcwi6PjmKfIsKKse9a3QQylAQIDJiABIVggzWmoG-7BjGBsAXMvYQoTOIVgKxRfKXikzM1Ke3xXufMiWCCIlv-cIuYiFA5kl2hKdTJtH39JQxVDC7jHSMLKJbwcBw");
	}

	@Test
	void publicKey() throws Exception {
		String hex = "a5010203262001215820cd69a81beec18c606c01732f610a133885602b145f2978a4cccd4a7b7c57b9f32258208896ff9c22e622140e6497684a75326d1f7f494315430bb8c748c2ca25bc1c07";
		byte[] bytes = BinaryUtil.fromHex(hex);

		PublicKey publicKey = WebAuthnCodecs.importCosePublicKey(new ByteArray(bytes));
		System.out.println(publicKey);
	}

	private static void clientData(String base64) throws IOException, Base64UrlException {
		byte[] decode = Base64.getUrlDecoder().decode(base64);
		CollectedClientData data = new CollectedClientData(new ByteArray(decode));
		System.out.println(data);
	}

	private static void attestationObject(String base64) throws IOException, Base64UrlException {
		byte[] decode = Base64.getUrlDecoder().decode(base64);
		AttestationObject attestationObject = new AttestationObject(new ByteArray(decode));
		System.out.println(attestationObject);
	}
}
