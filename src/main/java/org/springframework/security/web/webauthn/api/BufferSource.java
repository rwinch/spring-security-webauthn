package org.springframework.security.web.webauthn.api;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = BufferSourceSerializer.class)
public class BufferSource {
	private final byte[] bytes;

	public BufferSource(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] getBytes() {
		return this.bytes;
	}
}
