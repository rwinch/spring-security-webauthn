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

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.AuthenticatorTransport;
import org.springframework.security.webauthn.api.registration.COSEAlgorithmIdentifier;

public class TestAuthenticatorAttestationResponse {
	public static AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder createAuthenticatorAttestationResponse() {
		return AuthenticatorAttestationResponse.builder()
				.attestationObject(ArrayBuffer.fromBase64("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
				.clientDataJSON(ArrayBuffer.fromBase64("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
				.transports(AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL)
				.publicKeyAlgorithm(COSEAlgorithmIdentifier.ES256)
				.publicKey(ArrayBuffer.fromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkr7Z6k8TDS6Mc36C9WnYend5_wLNTfOrA7nKXHwvY6wrnHk6VMYQ_EtL7zlMAAG6bhqpUrgJJYnstgN2SO4EuQ"))
				.authenticatorData(ArrayBuffer.fromBase64("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"));
	}
}
