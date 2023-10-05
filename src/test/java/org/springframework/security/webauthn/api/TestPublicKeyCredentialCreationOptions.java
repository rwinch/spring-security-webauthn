package org.springframework.security.webauthn.api;

import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;

import java.time.Duration;

public class TestPublicKeyCredentialCreationOptions {
	public static PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder createPublicKeyCredentialCreationOptions() {

		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.DISCOURAGED)
				.build();
		BufferSource challenge = BufferSource.fromBase64("IBQnuY1Z0K1HqBoFWCp2xlJl8-oq_aFIXzyT_F0-0GU");
		PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
				.id("localhost")
				.name("SimpleWebAuthn Example")
				.build();
		BufferSource userId = BufferSource.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w");
		PublicKeyCredentialUserEntity userEntity = PublicKeyCredentialUserEntity.builder()
				.displayName("user@localhost")
				.id(userId)
				.name("user@localhost")
				.build();
		DefaultAuthenticationExtensionsClientInputs clientInputs = new DefaultAuthenticationExtensionsClientInputs();
		clientInputs.add(ImmutableAuthenticationExtensionsClientInput.credProps);
		return  PublicKeyCredentialCreationOptions.builder()
				.attestation(AttestationConveyancePreference.NONE)
				.user(userEntity)
				.pubKeyCredParams(PublicKeyCredentialParameters.RS256, PublicKeyCredentialParameters.ES256)
				.authenticatorSelection(authenticatorSelection)
				.challenge(challenge)
				.rp(rp)
				.extensions(clientInputs)
				.timeout(Duration.ofMillis(60000));
	}
}
