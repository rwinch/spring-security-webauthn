
/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.api.core;

import java.security.SecureRandom;
import java.util.Base64;

// FIXME: Consider replacing with UrlBase64String

public class BufferSource {

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private static final SecureRandom RANDOM = new SecureRandom();

	private final byte[] bytes;

	public BufferSource(byte[] bytes) {
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
		if (obj instanceof BufferSource buffer) {
			return buffer.getBytesAsBase64().equals(getBytesAsBase64());
		}
		return false;
	}

	@Override
	public String toString() {
		return "BufferSource[" + getBytesAsBase64() +"]";
	}

	public static BufferSource fromBase64(String base64String) {
		byte[] bytes = DECODER.decode(base64String);
		return new BufferSource(bytes);
	}

	public static BufferSource random() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return new BufferSource(bytes);
	}

}
