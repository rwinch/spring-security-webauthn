
/*
 * Copyright 2002-2024 the original author or authors.
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

/**
 * Represents a Base64 URL encoded String.
 * FIXME: Consider a new name it contains bytes that are raw and can be encoded as Base64 URL String
 */
public class Base64Url {

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

	private final byte[] bytes;

	/**
	 * Creates a new instance
	 * @param bytes the raw base64UrlString that will be encoded.
	 */
	public Base64Url(byte[] bytes) {
		Assert.notNull(bytes, "bytes cannot be null");
		this.bytes = bytes;
	}

	/**
	 * Gets the raw bytes.
	 * @return the bytes
	 */
	public byte[] getBytes() {
		return this.bytes;
	}

	/**
	 * Gets the bytes as Base64 URL encoded String.
	 * @return
	 */
	public String getBytesAsBase64() {
		return ENCODER.encodeToString(getBytes());
	}

	@Override
	public int hashCode() {
		return getBytesAsBase64().hashCode();
	}

	public String toString() {
		return "Base64Url[" + getBytesAsBase64() + "]";
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Base64Url buffer) {
			return buffer.getBytesAsBase64().equals(getBytesAsBase64());
		}
		return false;
	}

	/**
	 * Creates a secure random Base64Url with random bytes and sufficient entropy.
	 * @return a new secure random generated base64UrlString
	 */
	public static Base64Url random() {
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);
		return new Base64Url(bytes);
	}

	/**
	 * Creates a new instance from a base64 url string.
	 * @param base64UrlString the base64 url string
	 * @return the {@link Base64Url}
	 */
	public static Base64Url fromBase64(String base64UrlString) {
		byte[] bytes = DECODER.decode(base64UrlString);
		return new Base64Url(bytes);
	}

}
