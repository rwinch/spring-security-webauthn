package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;

@JsonDeserialize(builder = AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class)
class AuthenticatorAssertionResponseMixin {

	@JsonPOJOBuilder(withPrefix = "")
	abstract class AuthenticatorAssertionResponseBuilderMixin {
	}

}
