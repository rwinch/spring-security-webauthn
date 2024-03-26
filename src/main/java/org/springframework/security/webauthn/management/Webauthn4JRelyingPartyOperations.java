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
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.webauthn.api.AuthenticatorTransport;
import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.DefaultAuthenticationExtensionsClientInputs;
import org.springframework.security.webauthn.api.ImmutableAuthenticationExtensionsClientInput;
import org.springframework.security.webauthn.api.PublicKeyCredential;
import org.springframework.security.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.webauthn.api.UserVerificationRequirement;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class Webauthn4JRelyingPartyOperations implements WebAuthnRelyingPartyOperations {

	private WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

	private ObjectConverter objectConverter = new ObjectConverter();

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	private final Set<String> allowedOrigins;

	private final PublicKeyCredentialRpEntity rp;

	private Consumer<PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder> customizeCreationOptions = defaultCreationOptions();

	private Consumer<PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder> customizeRequestOptions = defaultRequestOptions();

	public Webauthn4JRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials, PublicKeyCredentialRpEntity rpEntity, Set<String> allowedOrigins) {
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
		this.rp = rpEntity;
		this.allowedOrigins = allowedOrigins;
	}

	public void setWebAuthnManager(WebAuthnManager webAuthnManager) {
		Assert.notNull(webAuthnManager, "webAuthnManager cannot be null");
		this.webAuthnManager = webAuthnManager;
	}

	public void setCustomizeRequestOptions(Consumer<PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder> customizeRequestOptions) {
		Assert.notNull(customizeRequestOptions, "customizeRequestOptions cannot be null");
		this.customizeRequestOptions = customizeRequestOptions;
	}

	public void setCustomizeCreationOptions(Consumer<PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder> customizeCreationOptions) {
		Assert.notNull(customizeCreationOptions, "customizeCreationOptions must not be null");
		this.customizeCreationOptions = customizeCreationOptions;
	}

	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<CredentialRecord> credentialRecords = this.userCredentials.findByUserId(userEntity.getId());

		PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
				.user(userEntity)
				.rp(this.rp)
				.excludeCredentials(credentialDescriptors(credentialRecords))
				.customize(this.customizeCreationOptions)
				.build();
		return options;
	}

	private static List<PublicKeyCredentialDescriptor> credentialDescriptors(List<CredentialRecord> credentialRecords) {
		List result = new ArrayList();
		for (CredentialRecord credentialRecord : credentialRecords) {
			Base64Url id = Base64Url.fromBase64(credentialRecord.getCredentialId().getBytesAsBase64());
			PublicKeyCredentialDescriptor credentialDescriptor = PublicKeyCredentialDescriptor.builder()
					.id(id)
					.transports(credentialRecord.getTransports())
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
	public CredentialRecord registerCredential(RelyingPartyRegistrationRequest rpRegistrationRequest) {
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
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData = registrationData.getAttestationObject().getAuthenticatorData();

		CborConverter cborConverter = this.objectConverter.getCborConverter();
		byte[] coseKey = cborConverter.writeValueAsBytes(authData.getAttestedCredentialData().getCOSEKey());
		ImmutableCredentialRecord userCredential = ImmutableCredentialRecord.builder()
				.userEntityUserId(creationOptions.getUser().getId())
				.credentialType(credential.getType())
				.credentialId(credential.getRawId())
				.publicKey(new ImmutablePublicKeyCose(coseKey))
				.signatureCount(authData.getSignCount())
				.uvInitialized(authData.isFlagUV())
				.transports(convertTransports(registrationData.getTransports()))
				.backupEligible(authData.isFlagBE())
				.backupState(authData.isFlagBS())
				.label(publicKey.getLabel())
				.attestationClientDataJSON(credential.getResponse().getClientDataJSON())
				.attestationObject(credential.getResponse().getAttestationObject())
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
		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<CredentialRecord> credentialRecords = this.userCredentials.findByUserId(userEntity.getId());
		return PublicKeyCredentialRequestOptions.builder()
				.allowCredentials(credentialDescriptors(credentialRecords))
				.challenge(Base64Url.random())
				.rpId(this.rp.getId())
				.customize(this.customizeRequestOptions)
				.build();
	}

	private static Consumer<PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder> defaultRequestOptions() {
		return options -> {
			options
				.timeout(Duration.ofMinutes(5))
				.userVerification(UserVerificationRequirement.REQUIRED);
		};
	}

	@Override
	public String authenticate(AuthenticationRequest request) {
		PublicKeyCredentialRequestOptions requestOptions = request.getRequestOptions();
		AuthenticatorAssertionResponse assertionResponse = request.getPublicKey().getResponse();
		Base64Url keyId = request.getPublicKey().getRawId();
		CredentialRecord credentialRecord = this.userCredentials.findByCredentialId(keyId);

		CborConverter cborConverter = this.objectConverter.getCborConverter();
		AttestationObject attestationObject = cborConverter.readValue(credentialRecord.getAttestationObject().getBytes(), AttestationObject.class);

		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData = attestationObject.getAuthenticatorData();
		AttestedCredentialData data = new AttestedCredentialData(authData.getAttestedCredentialData().getAaguid(), keyId.getBytes(), authData.getAttestedCredentialData().getCOSEKey());


		Authenticator authenticator = new AuthenticatorImpl(data, attestationObject.getAttestationStatement(), credentialRecord.getSignatureCount());
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}
		Set<Origin> origins = toOrigins();
		Challenge challenge = new DefaultChallenge(requestOptions.getChallenge().getBytes());
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origins,requestOptions.getRpId(), challenge, tokenBindingId);
		boolean userVerificationRequired = request.getRequestOptions().getUserVerification() == UserVerificationRequirement.REQUIRED;

		com.webauthn4j.data.AuthenticationRequest authenticationRequest = new com.webauthn4j.data.AuthenticationRequest(
				request.getPublicKey().getId().getBytes(),
				assertionResponse.getAuthenticatorData().getBytes(),
				assertionResponse.getClientDataJSON().getBytes(),
				assertionResponse.getSignature().getBytes()
		);
		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator, userVerificationRequired);

		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest, authenticationParameters);

		long updatedSignCount = authenticationData.getAuthenticatorData().getSignCount();
		if (updatedSignCount != credentialRecord.getSignatureCount()) {
			ImmutableCredentialRecord updatedRecord = ImmutableCredentialRecord.fromCredentialRecord(credentialRecord)
					.signatureCount(updatedSignCount)
					.build();
			this.userCredentials.save(updatedRecord);
		}

		return this.userEntities.findUsernameByUserEntityId(credentialRecord.getUserEntityUserId());
	}

	private static Consumer<PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder> defaultCreationOptions() {
		return options -> {
			AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
					.userVerification(UserVerificationRequirement.PREFERRED)
					.residentKey(ResidentKeyRequirement.REQUIRED)
					.build();

			DefaultAuthenticationExtensionsClientInputs clientInputs = new DefaultAuthenticationExtensionsClientInputs();
			clientInputs.add(ImmutableAuthenticationExtensionsClientInput.credProps);

			options
					.attestation(AttestationConveyancePreference.DIRECT)
					.pubKeyCredParams(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
					.authenticatorSelection(authenticatorSelection)
					.challenge(Base64Url.random())
					.extensions(clientInputs)
					.timeout(Duration.ofMinutes(10));
		};
	}

}
