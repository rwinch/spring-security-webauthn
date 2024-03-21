/*
 * Copyright 2002-2024 the original author or authors.
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

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.*;
import org.springframework.security.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.webauthn.api.AuthenticatorTransport;
import org.springframework.security.webauthn.api.PublicKeyCredential;
import org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

public class Webauthn4JRelyingPartyOperations implements WebAuthnRelyingPartyOperations {

	private final WebAuthnManager webAuthnManager = createManager();

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	private final Set<String> allowedOrigins;

	private final PublicKeyCredentialRpEntity rp;

	public Webauthn4JRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials, PublicKeyCredentialRpEntity rpEntity, Set<String> allowedOrigins) {
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
		this.rp = rpEntity;
		this.allowedOrigins = allowedOrigins;
	}

	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
// FIXME: exclude ids is it from attStmt?
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
	public UserCredential registerCredential(RelyingPartyRegistrationRequest rpRegistrationRequest) {
		PublicKeyCredentialCreationOptions creationOptions = rpRegistrationRequest.getCreationOptions();
		String rpId = creationOptions.getRp().getId();
		RelyingPartyPublicKey publicKey = rpRegistrationRequest.getPublicKey();
		PublicKeyCredential<AuthenticatorAttestationResponse> credential = publicKey.getCredential();
		AuthenticatorAttestationResponse response = credential.getResponse();
		// Server properties
		Set<Origin> origins = toOrigins();
		byte[] base64Challenge = creationOptions.getChallenge().getBytes();
		byte[] attestationObject = response.getAttestationObject().getBytes();
		byte[] clientDataJSON = response.getClientDataJSON().getBytes();
		Challenge challenge = new DefaultChallenge(base64Challenge);
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */; // FIXME: https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-tokenbinding
		ServerProperty serverProperty = new ServerProperty(origins, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = creationOptions.getAuthenticatorSelection().getUserVerification() == UserVerificationRequirement.REQUIRED;
		RegistrationRequest webauthn4jRegistrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);
		RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, userVerificationRequired);

		RegistrationData registrationData = this.webAuthnManager.validate(webauthn4jRegistrationRequest, registrationParameters);
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = registrationData.getAttestationObject().getAuthenticatorData();

		CborConverter cborConverter = new ObjectConverter().getCborConverter();
		byte[] coseKey = cborConverter.writeValueAsBytes(authenticatorData.getAttestedCredentialData().getCOSEKey());

		ImmutableUserCredential userCredential = ImmutableUserCredential.builder()
				.label(publicKey.getLabel())
				.credentialId(credential.getRawId())
				.userEntityUserId(creationOptions.getUser().getId())
				.publicKeyCose(new ImmutablePublicKeyCose(coseKey))
				.backupEligible(authenticatorData.isFlagBE())
				.backupState(authenticatorData.isFlagBS())
				.transports(convertTransports(registrationData.getTransports()))
				.build();
		this.userCredentials.save(userCredential);
		return userCredential;
	}

	private Set<Origin> toOrigins() {
		return this.allowedOrigins.stream().map(Origin::new).collect(Collectors.toSet());
	}

	private List<AuthenticatorTransport> convertTransports(Set<com.webauthn4j.data.AuthenticatorTransport> transports) {
		if (transports == null) {
			return Collections.emptyList();
		}
		return transports.stream()
				.map(t -> AuthenticatorTransport.valueOf(t.getValue()))
				.collect(Collectors.toUnmodifiableList());
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
		PublicKeyCredentialRequestOptions requestOptions = request.getRequestOptions();
		AuthenticatorAssertionResponse assertionResponse = request.getPublicKey().getResponse();
		Base64Url keyId = request.getPublicKey().getRawId();
		UserCredential userCredential = this.userCredentials.findByCredentialId(keyId);
		CborConverter cborConverter = new ObjectConverter().getCborConverter();
		COSEKey coseKey = cborConverter.readValue(userCredential.getPublicKeyCose().getBytes(), COSEKey.class);

		AttestedCredentialData data = new AttestedCredentialData(AAGUID.NULL, keyId.getBytes(), coseKey);


		Authenticator authenticator = new AuthenticatorImpl(data, null, userCredential.getSignatureCount());
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}
		Set<Origin> origins = toOrigins();
		Challenge challenge = new DefaultChallenge(requestOptions.getChallenge().getBytes());
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origins,requestOptions.getRpId(), challenge, tokenBindingId);
		boolean userVerificationRequired = false;

		com.webauthn4j.data.AuthenticationRequest authenticationRequest = new com.webauthn4j.data.AuthenticationRequest(
				request.getPublicKey().getId().getBytes(),
				assertionResponse.getAuthenticatorData().getBytes(),
				assertionResponse.getClientDataJSON().getBytes(),
				assertionResponse.getSignature().getBytes()
		);
		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator, userVerificationRequired);

		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest, authenticationParameters);
		authenticator.setCounter(authenticationData.getAuthenticatorData().getSignCount());
		// FIXME: update the counter in the repository

		return this.userEntities.findUsernameByUserEntityId(userCredential.getUserEntityUserId());
	}

	private static WebAuthnManager createManager() {

		ObjectConverter objectConverter = new ObjectConverter();
		// com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager() returns a com.webauthn4j.WebAuthnManager instance
		// which doesn't validate an attestation statement. It is recommended configuration for most web application.
		// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
		// WebAuthnRegistrationContextValidator and provide validators you like
		return com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
	}
}
