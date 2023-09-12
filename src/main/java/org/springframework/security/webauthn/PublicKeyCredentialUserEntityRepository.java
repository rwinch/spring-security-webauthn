package org.springframework.security.webauthn;

public interface PublicKeyCredentialUserEntityRepository {
	PublicKeyCredentialUserEntity findUserIdByUsername(String username);

	void save(String username, PublicKeyCredentialUserEntity userIdentity);
}
