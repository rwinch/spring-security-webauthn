package org.springframework.security.webauthn.management;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;

import java.io.IOException;
import java.time.Duration;
import java.util.*;

public class WebAuthnRelyingPartyOperations {
	private final CredentialRepository credentialRepository = new SpringSecurityCredentialRepository();

	private PublicKeyCredentialUserEntityRepository userEntities = new MapPublicKeyCredentialUserEntityRepository();

	private Map<String,RegisteredCredential> base64IdToRegisteredCredential = new HashMap<>();

	PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
			.id("localhost")
			.name("Spring Security Relying Party")
			.build();


	// FIXME: Pass in the host (can have an allow list), perhaps pass PublicKeyCredentialUserEntity
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		// FIXME: Remove hard coded values
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.REQUIRED) // REQUIRED
				.build();


		PublicKeyCredentialUserEntity userEntity = findOrCreateAndSave(authentication.getName());
		DefaultAuthenticationExtensionsClientInputs clientInputs = new DefaultAuthenticationExtensionsClientInputs();
		clientInputs.add(ImmutableAuthenticationExtensionsClientInput.credProps);
		PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
				.attestation(AttestationConveyancePreference.NONE)
				.user(userEntity)
				.pubKeyCredParams(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
				.authenticatorSelection(authenticatorSelection)
				.challenge(BufferSource.random())
				.rp(this.rp)
				.extensions(clientInputs)
				.timeout(Duration.ofMinutes(10))
				.build();
		return options;
	}

	private PublicKeyCredentialUserEntity findOrCreateAndSave(String username) {
		final PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(username);
		if (foundUserEntity != null) {
			return foundUserEntity;
		}

		PublicKeyCredentialUserEntity userEntity = PublicKeyCredentialUserEntity.builder()
					.displayName(username)
					.id(BufferSource.random())
					.name(username)
					.build();
		this.userEntities.save(username, userEntity);
		return userEntity;
	}

	public void registerCredential(RelyingPartyRegistrationRequest relyingPartyRegistrationRequest) {
		PublicKeyCredential<AuthenticatorAttestationResponse> credential = relyingPartyRegistrationRequest.getCredential();
		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions yubicoOptions = YubicoConverter.createCreationOptions(relyingPartyRegistrationRequest.getCreationOptions());

		RelyingParty rp = RelyingParty.builder()
				.identity(yubicoOptions.getRp())
				.credentialRepository(this.credentialRepository)
				.origins(Collections.singleton("http://localhost:8080"))
				.build();
		try {
			RegistrationResult registrationResult = rp.finishRegistration(FinishRegistrationOptions.builder()
					.request(yubicoOptions)
					.response(YubicoConverter.convertPublicKeyCredential(credential))
					.build());



			RegisteredCredential yubicoCredential = RegisteredCredential.builder()
					.credentialId(new ByteArray(credential.getRawId().getBytes()))
					.userHandle(new ByteArray(relyingPartyRegistrationRequest.getCreationOptions().getUser().getId().getBytes()))
					.publicKeyCose(registrationResult.getPublicKeyCose())
					.build();
			this.base64IdToRegisteredCredential.put(yubicoCredential.getCredentialId().getBase64Url(), yubicoCredential);
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

	public String authenticate(AuthenticationRequest request) {
		RelyingParty rp = RelyingParty.builder()
				.identity(YubicoConverter.rpIdentity(this.rp))
				.credentialRepository(this.credentialRepository)
				.origins(Collections.singleton("http://localhost:8080"))
				.build();

		try {
			AssertionResult assertionResult = rp.finishAssertion(YubicoConverter.convertFinish(request));
			if (assertionResult.isSuccess()) {
				return assertionResult.getUsername();
			}
			throw new RuntimeException("Not successful " + assertionResult);
		} catch (AssertionFailedException e) {
			throw new RuntimeException(e);
		}
	}

	class SpringSecurityCredentialRepository implements CredentialRepository {

		@Override
		public Set<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
			return null;
		}

		@Override
		public Optional<ByteArray> getUserHandleForUsername(String username) {
			PublicKeyCredentialUserEntity userEntity = WebAuthnRelyingPartyOperations.this.userEntities.findByUsername(username);
			return Optional.ofNullable(userEntity)
				.map(PublicKeyCredentialUserEntity::getId)
				.map(YubicoConverter::convertByteArray);
		}

		@Override
		public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
			BufferSource userId = new BufferSource(userHandle.getBytes());
			String username = WebAuthnRelyingPartyOperations.this.userEntities.findUsernameByUserEntityId(userId);
			return Optional.ofNullable(username); // authenticate
		}

		@Override
		public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
			RegisteredCredential registeredCredential = WebAuthnRelyingPartyOperations.this.base64IdToRegisteredCredential.get(credentialId.getBase64Url());
			return Optional.ofNullable(registeredCredential); // authenticate
		}

		@Override
		public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
			return Collections.emptySet(); // registration
		}
	}
}
