package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = PublicKeyCredentialTypeSerializer.class)
@JsonDeserialize(using = PublicKeyCredentialTypeDeserializer.class)
abstract class PublicKeyCredentialTypeMixin {
}
