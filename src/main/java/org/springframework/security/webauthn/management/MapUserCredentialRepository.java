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

import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.util.Assert;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A {@link Map} based implementation of {@link UserCredentialRepository}.
 * @since 6.3
 * @author Rob Winch
 */
public class MapUserCredentialRepository implements UserCredentialRepository {

	private final Map<Base64Url, CredentialRecord> credentialIdToUserCredential = new HashMap<>();

	private final Map<Base64Url,Set<Base64Url>> userEntityIdToUserCredentialIds = new HashMap<>();

	@Override
	public void delete(Base64Url credentialId) {
		CredentialRecord credentialRecord = this.credentialIdToUserCredential.remove(credentialId);
		if (credentialRecord != null) {
			Set<Base64Url> credentialIds = this.userEntityIdToUserCredentialIds.get(credentialRecord.getUserEntityUserId());
			if (credentialIds != null) {
				credentialIds.remove(credentialId);
			}
		}
	}

	@Override
	public void save(CredentialRecord credentialRecord) {
		Assert.notNull(credentialRecord, "credentialRecord cannot be null");
		this.credentialIdToUserCredential.put(credentialRecord.getCredentialId(), credentialRecord);
		this.userEntityIdToUserCredentialIds.computeIfAbsent(credentialRecord.getUserEntityUserId(), (id) -> new HashSet<>()).add(credentialRecord.getCredentialId());
	}

	@Override
	public CredentialRecord findByCredentialId(Base64Url credentialId) {
		Assert.notNull(credentialId, "credentialId cannot be null");
		return this.credentialIdToUserCredential.get(credentialId);
	}

	@Override
	public List<CredentialRecord> findByUserId(Base64Url userId) {
		Assert.notNull(userId, "userId cannot be null");
		Set<Base64Url> credentialIds = this.userEntityIdToUserCredentialIds.getOrDefault(userId, Collections.emptySet());
		return credentialIds.stream()
			.map(this::findByCredentialId)
			.collect(Collectors.toUnmodifiableList());
	}
}
