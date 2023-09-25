package org.springframework.security.webauthn.api.core;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Base64;

public class ArrayBuffer {
	private final byte[] bytes;

	public ArrayBuffer(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] getBytes() {
		return this.bytes;
	}

	@JsonCreator // FIXME: Externalize @JsonCreator
	public static ArrayBuffer fromBase64(String value) {
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		return new ArrayBuffer(bytes);
	}
}
