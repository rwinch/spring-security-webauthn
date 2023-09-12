package org.springframework.security.webauthn;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = BufferSourceSerializer.class) // FIXME This should be done via mixins
public class BufferSource {
	private final byte[] bytes;

	public BufferSource(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] getBytes() {
		return this.bytes;
	}
}
