package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialUserEntity;

public interface PublicKeyCredentialUserEntityRepository {

	String findUsernameByUserEntityId(BufferSource id);

	PublicKeyCredentialUserEntity findByUsername(String username);

	void save(String username, PublicKeyCredentialUserEntity userEntity);

}
