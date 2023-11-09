package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialUserEntity;

import java.util.HashMap;
import java.util.Map;

public class MapPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

	private final Map<String,PublicKeyCredentialUserEntity> usernameToUserEntity = new HashMap<>();

	private final Map<BufferSource,String> idToUsername = new HashMap<>();

	public MapPublicKeyCredentialUserEntityRepository() {
		System.out.println("created MPKCUER");
	}

	@Override
	public String findUsernameByUserEntityId(BufferSource id) {
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
