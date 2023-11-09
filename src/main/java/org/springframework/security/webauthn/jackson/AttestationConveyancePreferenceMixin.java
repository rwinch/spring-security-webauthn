package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = AttestationConveyancePreferenceSerializer.class)
class AttestationConveyancePreferenceMixin {
}
