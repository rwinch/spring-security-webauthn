
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

package org.springframework.security.webauthn.api;

import org.springframework.util.Assert;

import java.security.SecureRandom;
import java.util.Base64;

public class Base64Url {

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private final byte[] bytes;

	public Base64Url(byte[] bytes) {
		Assert.notNull(bytes, "bytes cannot be null");
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

	public String toString() {
		return "ArrayBuffer[" + getBytesAsBase64() + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Base64Url buffer) {
			return buffer.getBytesAsBase64().equals(getBytesAsBase64());
		}
		return false;
	}

	public static Base64Url random() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return new Base64Url(bytes);
	}

	public static Base64Url fromBase64(String value) {
		byte[] bytes = DECODER.decode(value);
		return new Base64Url(bytes);
	}
}
