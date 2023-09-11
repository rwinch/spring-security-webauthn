package org.springframework.security.web.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;

import java.util.Optional;
import java.util.Set;

public class InMemoryCredentialRepository implements CredentialRepository  {
	@Override
	public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
		return null;
	}

	@Override
	public Optional<ByteArray> getUserHandleForUsername(String username) {
		return Optional.empty();
	}

	@Override
	public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
		return Optional.empty();
	}

	@Override
	public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
		return Optional.empty();
	}

	@Override
	public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
		return null;
	}
}
