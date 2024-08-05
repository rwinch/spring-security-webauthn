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

import org.springframework.security.webauthn.api.Bytes;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;

/**
 * FIXME: only interfaces for inputs and outputs
 * A repository for managing {@link PublicKeyCredentialUserEntity} instances.
 * @since 6.4
 * @author Rob Winch
 */
public interface PublicKeyCredentialUserEntityRepository {

	/**
	 * Finds the {@link PublicKeyCredentialUserEntity} by {@link PublicKeyCredentialUserEntity#getId()}
	 * @param id the id to lookup the username by
	 * @return the username or null if not found.
	 */
	PublicKeyCredentialUserEntity findById(Bytes id);

	/**
	 * Finds the {@link PublicKeyCredentialUserEntity} by the username.
	 * @param username the username to lookup the {@link PublicKeyCredentialUserEntity}
	 * @return the {@link PublicKeyCredentialUserEntity} or null if not found.
	 */
	PublicKeyCredentialUserEntity findByUsername(String username);

	/**
	 * Saves the {@link PublicKeyCredentialUserEntity} to the associated username.
	 * @param userEntity the {@link PublicKeyCredentialUserEntity} to associate to the provided username. If null, any
	 * existing entry is deleted.
	 */
	void save(PublicKeyCredentialUserEntity userEntity);

	void delete(Bytes id);
}
