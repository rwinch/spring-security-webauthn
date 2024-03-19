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

import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;

import java.util.HashMap;
import java.util.Map;

public class MapPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

	private final Map<String,PublicKeyCredentialUserEntity> usernameToUserEntity = new HashMap<>();

	private final Map<Base64Url,String> idToUsername = new HashMap<>();

	@Override
	public String findUsernameByUserEntityId(Base64Url id) {
		return this.idToUsername.get(id);
	}

	@Override
	public PublicKeyCredentialUserEntity findByUsername(String username) {
		return this.usernameToUserEntity.get(username);
	}

	@Override
	public void save(String username, PublicKeyCredentialUserEntity userEntity) {
		this.usernameToUserEntity.put(username, userEntity);
		this.idToUsername.put(userEntity.getId(), username);
	}

}
