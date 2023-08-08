package org.springframework.security.web.webauthn;

import com.yubico.webauthn.data.UserIdentity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FIXME: This should be saved per Authentication
 *
 * @author Rob Winch
 */
public class WebAuthnRepository {


	private Map<String, PublicKeyCredentialUserEntity> usernameToUserId = new ConcurrentHashMap<>();

	public PublicKeyCredentialUserEntity  findUserIdByUsername(String username) {
		return this.usernameToUserId.get(username);
	}

	public void save(String username, PublicKeyCredentialUserEntity  userIdentity) {
		this.usernameToUserId.put(username, userIdentity);
	}
}
