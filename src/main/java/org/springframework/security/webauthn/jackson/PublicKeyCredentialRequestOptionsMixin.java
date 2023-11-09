package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.time.Duration;

@JsonInclude(content = JsonInclude.Include.NON_NULL)
class PublicKeyCredentialRequestOptionsMixin {
	@JsonSerialize(using = DurationSerializer.class)
	private final Duration timeout = null;
}
