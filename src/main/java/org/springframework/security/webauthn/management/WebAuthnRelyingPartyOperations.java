package org.springframework.security.webauthn.management;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

public class WebAuthnRelyingPartyOperations {
	PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
			.id("localhost")
			.name("SimpleWebAuthn Example")
			.build();

	// FIXME: Pass in the host, perhaps pass PublicKeyCredentialUserEntity
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		// FIXME: Remove hard coded values
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.REQUIRED) // REQUIRED
				.build();
		BufferSource challenge = BufferSource.fromBase64("IBQnuY1Z0K1HqBoFWCp2xlJl8-oq_aFIXzyT_F0-0GU");

		BufferSource userId = BufferSource.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w");
		PublicKeyCredentialUserEntity userEntity = PublicKeyCredentialUserEntity.builder()
				.displayName("user@localhost")
				.id(userId)
				.name("user@localhost")
				.build();
		DefaultAuthenticationExtensionsClientInputs clientInputs = new DefaultAuthenticationExtensionsClientInputs();
		clientInputs.add(ImmutableAuthenticationExtensionsClientInput.credProps);
		PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
				.attestation(AttestationConveyancePreference.NONE)
				.user(userEntity)
				.pubKeyCredParams(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
				.authenticatorSelection(authenticatorSelection)
				.challenge(challenge)
				.rp(this.rp)
				.extensions(clientInputs)
				.timeout(Duration.ofMinutes(10))
				.build();
		return options;
	}

	public void registerCredential(RegistrationRequest registrationRequest) {
		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions yubicoOptions = YubicoConverter.createCreationOptions(registrationRequest.getCreationOptions());

		RelyingParty rp = RelyingParty.builder()
				.identity(yubicoOptions.getRp())
				.credentialRepository(new InMemoryCredentialRepository())
				.origins(Collections.singleton("http://localhost:8080"))
				.build();
		try {
			rp.finishRegistration(FinishRegistrationOptions.builder()
					.request(yubicoOptions)
					.response(YubicoConverter.convertPublicKeyCredential(registrationRequest.getCredential()))
					.build());
			System.out.println("done");
		}
		catch (RegistrationFailedException | Base64UrlException | IOException f) {
			throw new RuntimeException(f);

		}

	}

	public PublicKeyCredentialRequestOptions createCredentialRequestOptions(Authentication authentication) {
		return PublicKeyCredentialRequestOptions.builder()
				.allowCredentials(Arrays.asList())
				.challenge(BufferSource.random())
				.rpId(this.rp.getId())
				.timeout(Duration.ofMinutes(5))
				.userVerification(UserVerificationRequirement.REQUIRED)
				.build();
	}

	public void authenticate(AuthenticationRequest request) {
		RelyingParty rp = RelyingParty.builder()
				.identity(YubicoConverter.rpIdentity(this.rp))
				.credentialRepository(new InMemoryCredentialRepository())
				.origins(Collections.singleton("http://localhost:8080"))
				.build();

		try {
			AssertionResult assertionResult = rp.finishAssertion(FinishAssertionOptions.builder()
					.request(AssertionRequest.builder()
						.publicKeyCredentialRequestOptions(YubicoConverter.createCreationOptions(request.getRequestOptions()))
							.build())
					.response(null)
					.build());
		} catch (AssertionFailedException e) {
			throw new RuntimeException(e);
		}
	}

	static class InMemoryCredentialRepository implements CredentialRepository {

		@Override
		public Set<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
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
			return Collections.emptySet();
		}
	}
}
