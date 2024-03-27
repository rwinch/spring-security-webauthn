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

package org.springframework.security.webauthn.management;

import java.util.Arrays;
import java.util.Base64;

public class ImmutablePublicKeyCose implements PublicKeyCose {
	private final byte[] bytes;

	public ImmutablePublicKeyCose(byte[] bytes) {
		this.bytes = Arrays.copyOf(bytes, bytes.length);
	}

	@Override
	public byte[] getBytes() {
		return Arrays.copyOf(this.bytes, this.bytes.length);
	}

	public static ImmutablePublicKeyCose fromBase64(String base64) {
		byte[] decode = Base64.getUrlDecoder().decode(base64);
		return new ImmutablePublicKeyCose(decode);
	}
}
