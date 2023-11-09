package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;

abstract class RelyingPartyPublicKeyMixin {
	RelyingPartyPublicKeyMixin(@JsonProperty("credential") PublicKeyCredential<AuthenticatorAttestationResponse> credential, @JsonProperty("label") String label) {
	}
}
