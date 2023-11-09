package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = UserVerificationRequirementSerializer.class)
abstract class UserVerificationRequirementMixin {
}
