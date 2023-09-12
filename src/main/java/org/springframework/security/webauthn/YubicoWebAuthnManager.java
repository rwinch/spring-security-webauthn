package org.springframework.security.webauthn;

import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import org.springframework.security.core.Authentication;

import java.security.SecureRandom;
import java.util.Arrays;

public class YubicoWebAuthnManager implements WebAuthnManager {
	private SecureRandom random = new SecureRandom();

	private PublicKeyCredentialRpEntity relyingParty = PublicKeyCredentialRpEntity.builder()
			.id("localhost")
			.name("ACME Corporation")
			.build();

	private PublicKeyCredentialUserEntityRepository userEntityRepository;

	public YubicoWebAuthnManager(PublicKeyCredentialUserEntityRepository userEntityRepository) {
		this.userEntityRepository = userEntityRepository;
	}

	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		String username = authentication.getName();

		// FIXME: Perhaps (but think I changed my mind) Pass PublicKeyCredentialUserEntity instead of Authentication to avoid lookups in a manager.
		PublicKeyCredentialUserEntity userIdentity = userIdentity(username);
		PublicKeyCredentialCreationOptions result = PublicKeyCredentialCreationOptions.builder()
				.rp(this.relyingParty)
				.user(userIdentity)
				.challenge(new BufferSource(randomBytes()))
				.pubKeyCredParams(Arrays.asList(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256))
				.build();
		return result;
	}

	private PublicKeyCredentialUserEntity  userIdentity(String username) {
		PublicKeyCredentialUserEntity  savedUserIdentity = this.userEntityRepository.findUserIdByUsername(username);
		if (savedUserIdentity != null) {
			return savedUserIdentity;
		}
		PublicKeyCredentialUserEntity toRegister = PublicKeyCredentialUserEntity.builder()
				.name(username)
				.displayName(username)
				.id(new BufferSource(randomBytes()))
				.build();
		this.userEntityRepository.save(username, toRegister);
		return toRegister;
	}

	private byte[] randomBytes() {
		byte[] result = new byte[64];
		this.random.nextBytes(result);
		return result;
	}
}
