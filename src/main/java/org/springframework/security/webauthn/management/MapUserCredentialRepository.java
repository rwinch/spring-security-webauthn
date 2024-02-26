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

package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;

import java.util.*;

public class MapUserCredentialRepository implements UserCredentialRepository {

	private final Map<ArrayBuffer,UserCredential> credentialIdToUserCredential = new HashMap<>();

	private final Map<BufferSource,List<UserCredential>> userEntityIdToUserCredentials = new HashMap<>();

	@Override
	public void delete(ArrayBuffer credentialId) {
		UserCredential userCredential = this.credentialIdToUserCredential.remove(credentialId);
		if (userCredential != null) {
			List<UserCredential> userCredentials = this.userEntityIdToUserCredentials.get(userCredential.getUserEntityUserId());
			if (userCredentials != null) {
				userCredentials.remove(userCredential);
			}
		}
	}

	@Override
	public void save(UserCredential userCredential) {
		this.credentialIdToUserCredential.put(userCredential.getCredentialId(), userCredential);
		this.userEntityIdToUserCredentials.computeIfAbsent(userCredential.getUserEntityUserId(), (id) -> new ArrayList<>()).add(userCredential);
	}

	@Override
	public UserCredential findByCredentialId(ArrayBuffer credentialId) {
		return this.credentialIdToUserCredential.get(credentialId);
	}

	@Override
	public List<UserCredential> findByUserId(BufferSource userId) {
		return Collections.unmodifiableList(this.userEntityIdToUserCredentials.getOrDefault(userId, Collections.emptyList()));
	}
}
