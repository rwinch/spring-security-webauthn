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

package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.webauthn.api.Base64Url;

/**
 * Jackson mixin for {@link org.springframework.security.webauthn.api.Base64Url}
 * @since 6.3
 * @author Rob Winch
 */
@JsonSerialize(using = Base64Serializer.class)
class Base64UrlMixin {
	@JsonCreator
	public static Base64Url fromBase64(String value) {
		return Base64Url.fromBase64(value);
	}
}
