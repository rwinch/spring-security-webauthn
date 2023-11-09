package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;

@JsonDeserialize(builder = PublicKeyCredential.PublicKeyCredentialBuilder.class)
class PublicKeyCredentialMixin {

	@JsonPOJOBuilder(withPrefix = "")
	static class PublicKeyCredentialBuilderMixin {}
}
