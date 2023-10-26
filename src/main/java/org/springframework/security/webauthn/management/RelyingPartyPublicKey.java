package org.springframework.security.webauthn.management;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;

public class RelyingPartyPublicKey {

	private final PublicKeyCredential<AuthenticatorAttestationResponse> credential;

	private final String label;

	// FIXME: Externalize Json
	@JsonCreator
	public RelyingPartyPublicKey(@JsonProperty("credential") PublicKeyCredential<AuthenticatorAttestationResponse> credential, @JsonProperty("label") String label) {
		this.credential = credential;
		this.label = label;
	}

	public PublicKeyCredential<AuthenticatorAttestationResponse> getCredential() {
		return this.credential;
	}

	public String getLabel() {
		return this.label;
	}
}
