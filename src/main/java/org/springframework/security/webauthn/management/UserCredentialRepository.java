package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;

import java.util.List;

public interface UserCredentialRepository {

	void delete(ArrayBuffer credentialId);

	void save(UserCredential userCredential);

	UserCredential findByCredentialId(ArrayBuffer credentialId);

	List<UserCredential> findByUserId(BufferSource userId);
}
