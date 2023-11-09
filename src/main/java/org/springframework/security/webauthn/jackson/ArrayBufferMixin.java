package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import org.springframework.security.webauthn.api.core.ArrayBuffer;

class ArrayBufferMixin {
	@JsonCreator
	public static ArrayBuffer fromBase64(String value) {
		return ArrayBuffer.fromBase64(value);
	}
}
