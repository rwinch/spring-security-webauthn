package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonDeserialize(using = AuthenticatorAttachmentDeserializer.class)
@JsonSerialize(using = AuthenticatorAttachmentSerializer.class)
class AuthenticatorAttachmentMixin {
}
