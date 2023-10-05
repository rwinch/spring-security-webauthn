package org.springframework.security.webauthn.management;

import java.util.Arrays;

public class ImmutablePublicKeyCose implements PublicKeyCose {
	private final byte[] bytes;

	public ImmutablePublicKeyCose(byte[] bytes) {
		this.bytes = Arrays.copyOf(bytes, bytes.length);
	}

	@Override
	public byte[] getBytes() {
		return Arrays.copyOf(this.bytes, this.bytes.length);
	}
}
