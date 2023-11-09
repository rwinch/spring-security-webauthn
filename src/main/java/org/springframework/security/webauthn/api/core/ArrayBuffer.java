
package org.springframework.security.webauthn.api.core;

import java.util.Base64;

// FIXME: Consider replacing with UrlBase64String
public class ArrayBuffer {

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private final byte[] bytes;

	public ArrayBuffer(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] getBytes() {
		return this.bytes;
	}

	public String getBytesAsBase64() {
		return ENCODER.encodeToString(getBytes());
	}
	@Override
	public int hashCode() {
		return getBytesAsBase64().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ArrayBuffer buffer) {
			return buffer.getBytesAsBase64().equals(getBytesAsBase64());
		}
		return false;
	}


	public static ArrayBuffer fromBase64(String value) {
		byte[] bytes = Base64.getUrlDecoder().decode(value);
		return new ArrayBuffer(bytes);
	}
}
