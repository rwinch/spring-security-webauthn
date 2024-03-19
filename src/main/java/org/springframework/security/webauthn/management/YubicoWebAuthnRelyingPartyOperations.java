/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.management;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.*;

import java.io.IOException;
import java.time.Duration;
import java.util.*;

public class YubicoWebAuthnRelyingPartyOperations implements WebAuthnRelyingPartyOperations {
	private final CredentialRepository credentialRepository = new SpringSecurityCredentialRepository();

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	private final Set<String> allowedOrigins;

	private final PublicKeyCredentialRpEntity rp;

	public YubicoWebAuthnRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials, PublicKeyCredentialRpEntity rpEntity, Set<String> allowedOrigins) {
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
		this.rp = rpEntity;
		this.allowedOrigins = allowedOrigins;
	}

	// FIXME: Pass in the host (can have an allow list), perhaps pass PublicKeyCredentialUserEntity
	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {

		// FIXME: Remove hard coded values
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
//				.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM) // specifying this just limits to either platform or cross platform
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.REQUIRED) // REQUIRED
				.build();


		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<UserCredential> userCredentials = this.userCredentials.findByUserId(userEntity.getId());
		DefaultAuthenticationExtensionsClientInputs clientInputs = new DefaultAuthenticationExtensionsClientInputs();
		clientInputs.add(ImmutableAuthenticationExtensionsClientInput.credProps);
		PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
				.attestation(AttestationConveyancePreference.DIRECT)
				.user(userEntity)
				.pubKeyCredParams(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
				.authenticatorSelection(authenticatorSelection)
				.challenge(Base64Url.random())
				.rp(this.rp)
				.extensions(clientInputs)
				.excludeCredentials(convertCredentials(userCredentials))
				.timeout(Duration.ofMinutes(10))
				.build();
		return options;
	}

	private List<PublicKeyCredentialDescriptor> convertCredentials(List<UserCredential> userCredentials) {
		List result = new ArrayList();
		for (UserCredential userCredential : userCredentials) {
			Base64Url id = Base64Url.fromBase64(userCredential.getCredentialId().getBytesAsBase64());
			PublicKeyCredentialDescriptor credentialDescriptor = PublicKeyCredentialDescriptor.builder()
				.id(id)
				.transports(userCredential.getTransports())
				.build();
			result.add(credentialDescriptor);
		}
		return result;
	}

	private PublicKeyCredentialUserEntity findUserEntityOrCreateAndSave(String username) {
		final PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(username);
		if (foundUserEntity != null) {
			return foundUserEntity;
		}

		PublicKeyCredentialUserEntity userEntity = PublicKeyCredentialUserEntity.builder()
					.displayName(username)
					.id(Base64Url.random())
					.name(username)
					.build();
		this.userEntities.save(username, userEntity);
		return userEntity;
	}

	@Override
	public UserCredential registerCredential(RelyingPartyRegistrationRequest relyingPartyRegistrationRequest) {
		RelyingPartyPublicKey registrationRequest = relyingPartyRegistrationRequest.getPublicKey();
		PublicKeyCredential<AuthenticatorAttestationResponse> credential = registrationRequest.getCredential();
		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions yubicoOptions = YubicoConverter.createCreationOptions(relyingPartyRegistrationRequest.getCreationOptions());

		try {
			RegistrationResult registrationResult = createYubicoRelyingParty().finishRegistration(FinishRegistrationOptions.builder()
					.request(yubicoOptions)
					.response(YubicoConverter.convertPublicKeyCredential(credential))
					.build());

			ImmutableUserCredential userCredential = ImmutableUserCredential.builder()
					.label(registrationRequest.getLabel())
					.credentialId(credential.getRawId())
					.userEntityUserId(relyingPartyRegistrationRequest.getCreationOptions().getUser().getId())
					.publicKeyCose(new ImmutablePublicKeyCose(registrationResult.getPublicKeyCose().getBytes()))
					.backupEligible(OptionalBoolean.fromBoolean(registrationResult.isBackupEligible()))
					.backupState(OptionalBoolean.fromBoolean(registrationResult.isBackedUp()))
					.transports(YubicoConverter.transports(registrationResult.getKeyId().getTransports()))
					.build();
			this.userCredentials.save(userCredential);
			return userCredential;
		}
		catch (RegistrationFailedException | Base64UrlException | IOException f) {
			throw new RuntimeException(f);

		}


	}

	@Override
	public PublicKeyCredentialRequestOptions createCredentialRequestOptions(Authentication authentication) {
		return PublicKeyCredentialRequestOptions.builder()
				.allowCredentials(Arrays.asList())
				.challenge(Base64Url.random())
				.rpId(this.rp.getId())
				.timeout(Duration.ofMinutes(5))
				.userVerification(UserVerificationRequirement.REQUIRED)
				.build();
	}

	@Override
	public String authenticate(AuthenticationRequest request) {
		try {
			AssertionResult assertionResult = createYubicoRelyingParty().finishAssertion(YubicoConverter.convertFinish(request));
			if (assertionResult.isSuccess()) {
				return assertionResult.getUsername();
			}
			throw new RuntimeException("Not successful " + assertionResult);
		} catch (AssertionFailedException e) {
			throw new RuntimeException(e);
		}
	}

	private RelyingParty createYubicoRelyingParty() {
		return RelyingParty.builder()
				.identity(YubicoConverter.rpIdentity(this.rp))
				.credentialRepository(this.credentialRepository)
				.origins(this.allowedOrigins)
//				.allowUntrustedAttestation(false)
//				.attestationTrustSource((List< X509Certificate > attestationCertificateChain, Optional<ByteArray> aaguid) -> {
//					return AttestationTrustSource.TrustRootsResult.builder().trustRoots(Collections.emptySet()).build();
//				})
				// FIXME: how to configure other properties
				.build();
	}

	class SpringSecurityCredentialRepository implements CredentialRepository {

		@Override
		public Set<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
			return null;
		}

		@Override
		public Optional<ByteArray> getUserHandleForUsername(String username) {
			PublicKeyCredentialUserEntity userEntity = YubicoWebAuthnRelyingPartyOperations.this.userEntities.findByUsername(username);
			return Optional.ofNullable(userEntity)
				.map(PublicKeyCredentialUserEntity::getId)
				.map(YubicoConverter::convertByteArray);
		}

		@Override
		public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
			Base64Url userId = new Base64Url(userHandle.getBytes());
			String username = YubicoWebAuthnRelyingPartyOperations.this.userEntities.findUsernameByUserEntityId(userId);
			return Optional.ofNullable(username); // authenticate
		}

		@Override
		public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
			RegisteredCredential registeredCredential = findById(credentialId);
			return Optional.ofNullable(registeredCredential); // authenticate
		}

		@Override
		public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
			return lookup(credentialId, null)
					.map(Collections::singleton)
					.orElse(Collections.emptySet()); // registration
		}

		private RegisteredCredential findById(ByteArray credentialId) {
			UserCredential credential = YubicoWebAuthnRelyingPartyOperations.this.userCredentials.findByCredentialId(new Base64Url(credentialId.getBytes()));
			if (credential == null) {
				return null;
			}
			return RegisteredCredential.builder()
					.credentialId(YubicoConverter.convertByteArray(credential.getCredentialId()))
					.userHandle(YubicoConverter.convertByteArray(credential.getUserEntityUserId()))
					.publicKeyCose(new ByteArray(credential.getPublicKeyCose().getBytes()))
					.signatureCount(credential.getSignatureCount())
					.backupEligible(credential.getBackupEligible().getValue())
					.backupState(credential.getBackupState().getValue())
					.build();
		}
	}
}
