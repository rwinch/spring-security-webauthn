package org.springframework.security.webauthn.api;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.registration.*;

public class TestPublicKeyCredential {

	public static PublicKeyCredential.PublicKeyCredentialBuilder<AuthenticatorAttestationResponse> createPublicKeyCredential() {
		AuthenticatorAttestationResponse response = TestAuthenticatorAttestationResponse.createAuthenticatorAttestationResponse().build();
		return createPublicKeyCredential(response);
	}

	public static <R extends AuthenticatorResponse> PublicKeyCredential.PublicKeyCredentialBuilder<R> createPublicKeyCredential(R response) {
		DefaultAuthenticationExtensionsClientOutputs clientExtensionResults = new DefaultAuthenticationExtensionsClientOutputs();
		clientExtensionResults.add(new CredentialPropertiesOutput(false));
		return PublicKeyCredential.builder()
				.id("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM")
				.rawId(ArrayBuffer.fromBase64("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM"))
				.response(response)
				.type(PublicKeyCredentialType.PUBLIC_KEY)
				.clientExtensionResults(clientExtensionResults);
	}
}
