package org.springframework.security.web.webauthn;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

public interface PublicKeyCredentialUserEntityRepository {
	PublicKeyCredentialUserEntity findUserIdByUsername(String username);

	void save(String username, PublicKeyCredentialUserEntity userIdentity);
}
