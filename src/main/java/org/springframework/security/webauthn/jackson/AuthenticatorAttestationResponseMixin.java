package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;

@JsonDeserialize(builder = AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder.class) // FIXME: Externalize @JsonDeserialize
class AuthenticatorAttestationResponseMixin {
}
