package org.springframework.security.webauthn.jackson;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.time.Duration;

@JsonInclude(JsonInclude.Include.NON_NULL)
abstract class PublicKeyCredentialCreationOptionsMixin {
	@JsonSerialize(using = DurationSerializer.class)
	private Duration timeout;

}
