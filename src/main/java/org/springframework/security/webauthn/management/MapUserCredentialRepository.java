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

import java.util.*;

/**
 * A {@link Map} based implementation of {@link UserCredentialRepository}.
 * @since 6.3
 * @author Rob Winch
 */
public class MapUserCredentialRepository implements UserCredentialRepository {

	private final Map<Base64Url, CredentialRecord> credentialIdToUserCredential = new HashMap<>();

	private final Map<Base64Url,List<CredentialRecord>> userEntityIdToUserCredentials = new HashMap<>();

	@Override
	public void delete(Base64Url credentialId) {
		CredentialRecord credentialRecord = this.credentialIdToUserCredential.remove(credentialId);
		if (credentialRecord != null) {
			List<CredentialRecord> credentialRecords = this.userEntityIdToUserCredentials.get(credentialRecord.getUserEntityUserId());
			if (credentialRecords != null) {
				credentialRecords.remove(credentialRecord);
			}
		}
	}

	@Override
	public void save(CredentialRecord credentialRecord) {
		this.credentialIdToUserCredential.put(credentialRecord.getCredentialId(), credentialRecord);
		this.userEntityIdToUserCredentials.computeIfAbsent(credentialRecord.getUserEntityUserId(), (id) -> new ArrayList<>()).add(credentialRecord);
	}

	@Override
	public CredentialRecord findByCredentialId(Base64Url credentialId) {
		return this.credentialIdToUserCredential.get(credentialId);
	}

	@Override
	public List<CredentialRecord> findByUserId(Base64Url userId) {
		return Collections.unmodifiableList(this.userEntityIdToUserCredentials.getOrDefault(userId, Collections.emptyList()));
	}
}
