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

import org.junit.jupiter.api.Test;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.api.TestPublicKeyCredentialUserEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link MapPublicKeyCredentialUserEntityRepository}.
 * @since 6.4
 * @author Rob Winch
 */
class MapPublicKeyCredentialUserEntityRepositoryTests {

	private MapPublicKeyCredentialUserEntityRepository userEntities = new MapPublicKeyCredentialUserEntityRepository();
	private PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
	private String username = "username";

	@Test
	void findUsernameByUserEntityIdWhenExistsThenFound() {
		this.userEntities.save(this.username, this.userEntity);
		String foundUsername = this.userEntities.findUsernameByUserEntityId(this.userEntity.getId());
		assertThat(foundUsername).isEqualTo(this.username);
	}

	@Test
	void findUsernameByUserEntityIdWhenDoesNotExistThenNull() {
		String foundUsername = this.userEntities.findUsernameByUserEntityId(this.userEntity.getId());
		assertThat(foundUsername).isNull();
	}

	@Test
	void findByUsernameWhenExistsThenFound() {
		this.userEntities.save(this.username, this.userEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(this.userEntity);
	}

	@Test
	void findByUsernameReturnsNullWhenUsernameDoesNotExist() {
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isNull();
	}

	@Test
	void saveWhenNonNullThenSuccess() {
		this.userEntities.save(this.username, this.userEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(this.userEntity);
	}

	@Test
	void saveWhenUpdateThenUpdated() {
		PublicKeyCredentialUserEntity newUserEntity = TestPublicKeyCredentialUserEntity.userEntity()
			.displayName("Updated")
			.build();
		this.userEntities.save(this.username, this.userEntity);
		this.userEntities.save(this.username, newUserEntity);
		PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(this.username);
		assertThat(foundUserEntity).isEqualTo(newUserEntity);
	}

	@Test
	void saveWhenNullThenRemovesExistingEntry() {
		this.userEntities.save(this.username, this.userEntity);
		this.userEntities.save(this.username, null);
		assertThat(this.userEntities.findByUsername(this.username)).isNull();
		assertThat(this.userEntities.findUsernameByUserEntityId(this.userEntity.getId())).isNull();
	}

	@Test
	void saveWhenNullAndDOesNotExistThenNoException() {
		assertThatNoException().isThrownBy(() -> this.userEntities.save(this.username, null));
	}
}
