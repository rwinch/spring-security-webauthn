package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(using = AuthenticatorTransportDeserializer.class)
class AuthenticatorTransportMixin {
}
