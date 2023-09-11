package org.springframework.security.web.webauthn;

import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FIXME: This should be saved per Authentication
 *
 * @author Rob Winch
 */
public class MapPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {


	private Map<String, PublicKeyCredentialUserEntity> usernameToUserId = new ConcurrentHashMap<>();

	@Override
	public PublicKeyCredentialUserEntity  findUserIdByUsername(String username) {
		return this.usernameToUserId.get(username);
	}

	@Override
	public void save(String username, PublicKeyCredentialUserEntity userIdentity) {
		this.usernameToUserId.put(username, userIdentity);
	}
}
