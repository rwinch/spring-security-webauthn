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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttachment;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.AuthenticatorSelectionCriteria;
import org.springframework.security.webauthn.api.registration.AuthenticatorTransport;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialDescriptor;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialParameters;
import org.springframework.security.webauthn.api.registration.ResidentKeyRequirement;
import org.springframework.security.webauthn.api.registration.UserVerificationRequirement;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

final class YubicoConverter {

	static com.yubico.webauthn.data.PublicKeyCredentialCreationOptions createCreationOptions(PublicKeyCredentialCreationOptions creationOptions ) {
		RelyingPartyIdentity rpIdentity = rpIdentity(creationOptions.getRp());
		PublicKeyCredentialUserEntity user = creationOptions.getUser();
		return com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.builder()
				.rp(rpIdentity)
				.user(createUser(user))
				.challenge(new ByteArray(creationOptions.getChallenge().getBytes()))
				.pubKeyCredParams(YubicoConverter.convertPublicKeyCredential(creationOptions.getPubKeyCredParams()))
				.authenticatorSelection(convertAuthenticationSelectorCriteria(creationOptions.getAuthenticatorSelection()))
				.attestation(YubicoConverter.convertAttestation(creationOptions.getAttestation()))
				.build();
	}

	private static AttestationConveyancePreference convertAttestation(org.springframework.security.webauthn.api.registration.AttestationConveyancePreference attestation) {
		if (attestation == org.springframework.security.webauthn.api.registration.AttestationConveyancePreference.DIRECT) {
			return AttestationConveyancePreference.DIRECT;
		}
		if (attestation == org.springframework.security.webauthn.api.registration.AttestationConveyancePreference.ENTERPRISE) {
			return AttestationConveyancePreference.ENTERPRISE;
		}
		if (attestation == org.springframework.security.webauthn.api.registration.AttestationConveyancePreference.INDIRECT) {
			return AttestationConveyancePreference.INDIRECT;
		}
		if (attestation == org.springframework.security.webauthn.api.registration.AttestationConveyancePreference.NONE) {
			return AttestationConveyancePreference.NONE;
		}
		return null;
	}

	private static com.yubico.webauthn.data.AuthenticatorSelectionCriteria convertAuthenticationSelectorCriteria(AuthenticatorSelectionCriteria authenticatorSelection) {
		if (authenticatorSelection == null) {
			return null;
		}
		return com.yubico.webauthn.data.AuthenticatorSelectionCriteria.builder()
				.userVerification(convertUserVerivication(authenticatorSelection.getUserVerification()))
				.authenticatorAttachment(convertAuthenticatorAttachment(authenticatorSelection.getAuthenticatorAttachment()))
				.residentKey(convertResidentKey(authenticatorSelection.getResidentKey()))
				.build();
	}

	private static com.yubico.webauthn.data.ResidentKeyRequirement convertResidentKey(ResidentKeyRequirement residentKey) {
		if (ResidentKeyRequirement.PREFERRED == residentKey) {
			return com.yubico.webauthn.data.ResidentKeyRequirement.PREFERRED;
		}
		if (ResidentKeyRequirement.DISCOURAGED == residentKey) {
			return com.yubico.webauthn.data.ResidentKeyRequirement.DISCOURAGED;
		}
		if (ResidentKeyRequirement.DISCOURAGED == residentKey) {
			return com.yubico.webauthn.data.ResidentKeyRequirement.DISCOURAGED;
		}
		return null;
	}

	private static com.yubico.webauthn.data.AuthenticatorAttachment convertAuthenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
		if (AuthenticatorAttachment.PLATFORM == authenticatorAttachment) {
			return com.yubico.webauthn.data.AuthenticatorAttachment.PLATFORM;
		}
		if (AuthenticatorAttachment.CROSS_PLATFORM == authenticatorAttachment) {
			return com.yubico.webauthn.data.AuthenticatorAttachment.CROSS_PLATFORM;
		}
		return null;
	}

	private static UserIdentity createUser(PublicKeyCredentialUserEntity user) {
		return UserIdentity.builder()
				.name(user.getName())
				.displayName(user.getDisplayName())
				.id(new ByteArray(user.getId().getBytes()))
				.build();
	}

	static RelyingPartyIdentity rpIdentity(PublicKeyCredentialRpEntity creationOptionsRp) {
		return RelyingPartyIdentity.builder()
				.id(creationOptionsRp.getId())
				.name(creationOptionsRp.getName())
				.build();
	}
	static com.yubico.webauthn.data.PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> convertPublicKeyCredential(PublicKeyCredential<AuthenticatorAttestationResponse> credential) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.PublicKeyCredential.<com.yubico.webauthn.data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
				.id(new ByteArray(credential.getRawId().getBytes()))
				.response(convertAttestationResponse(credential.getResponse()))
				.clientExtensionResults(convertClientExtensionResults(credential.getClientExtensionResults()))
				.build();
	}

	private static ClientRegistrationExtensionOutputs convertClientExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
		ClientRegistrationExtensionOutputs.ClientRegistrationExtensionOutputsBuilder result = ClientRegistrationExtensionOutputs.builder();
		if (clientExtensionResults != null) {
			clientExtensionResults.getOutputs().forEach(output -> {
				registerOutputWithBuilder(output, result);
			});
		}
		return result.build();
	}

	private static void registerOutputWithBuilder(AuthenticationExtensionsClientOutput<?> output, ClientRegistrationExtensionOutputs.ClientRegistrationExtensionOutputsBuilder result) {
		if (output instanceof CredentialPropertiesOutput credentialPropertiesOutput) {
			Extensions.CredentialProperties.CredentialPropertiesOutput yubicoOutput = Extensions.CredentialProperties.CredentialPropertiesOutput.builder()
					.rk(credentialPropertiesOutput.getOutput().isRk())
					.build();
			result.credProps(yubicoOutput);
		}
	}

	private static com.yubico.webauthn.data.AuthenticatorAttestationResponse convertAttestationResponse(AuthenticatorAttestationResponse response) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.AuthenticatorAttestationResponse.builder()
				.attestationObject(new ByteArray(response.getAttestationObject().getBytes()))
				.clientDataJSON(new ByteArray(response.getClientDataJSON().getBytes()))
				.transports(convertTransports(response.getTransports()))
				.build();
	}

	private static Set<com.yubico.webauthn.data.AuthenticatorTransport> convertTransports(List<AuthenticatorTransport> transports) {
		return transports.stream()
				.map(YubicoConverter::convertTransport)
				.collect(Collectors.toSet());
	}

	private static com.yubico.webauthn.data.AuthenticatorTransport convertTransport(AuthenticatorTransport authenticatorTransport) {
		return com.yubico.webauthn.data.AuthenticatorTransport.HYBRID;
	}


	static List<com.yubico.webauthn.data.PublicKeyCredentialParameters> convertPublicKeyCredential(List<PublicKeyCredentialParameters> pubKeyCredParams) {
		return pubKeyCredParams.stream()
				.map(YubicoConverter::convertPublicKeyCredential)
				.collect(Collectors.toList());
	}

	private static com.yubico.webauthn.data.PublicKeyCredentialParameters convertPublicKeyCredential(PublicKeyCredentialParameters parameters) {
		if (PublicKeyCredentialParameters.EdDSA.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.EdDSA;
		}
		else if (PublicKeyCredentialParameters.ES256.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.ES256;
		}
		else if (PublicKeyCredentialParameters.ES384.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.ES384;
		}
		else if (PublicKeyCredentialParameters.ES512.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.ES512;
		}
		else if (PublicKeyCredentialParameters.RS256.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.RS256;
		}
		else if (PublicKeyCredentialParameters.RS384.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.RS384;
		}
		else if (PublicKeyCredentialParameters.RS512.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.RS512;
		}
		else if (PublicKeyCredentialParameters.RS1.equals(parameters)) {
			return com.yubico.webauthn.data.PublicKeyCredentialParameters.RS1;
		}
		throw new IllegalStateException("Unable to convert " + parameters);
	}
	private YubicoConverter() {}

	public static FinishAssertionOptions convertFinish(AuthenticationRequest request) {
		try {
			return FinishAssertionOptions.builder()
					.request(convertAssertionRequest(request.getRequestOptions()))
					.response(convertResponse(request.getPublicKey()))
					.build();
		} catch (Base64UrlException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static com.yubico.webauthn.data.PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> convertResponse(PublicKeyCredential<org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse> publicKey) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.PublicKeyCredential.<com.yubico.webauthn.data.AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
				.id(convertByteArray(publicKey.getRawId()))
				.response(convertResponse(publicKey.getResponse()))
				.clientExtensionResults(convertClientAssertionExtensionResults(publicKey.getClientExtensionResults()))
				.build();
	}

	private static ClientAssertionExtensionOutputs convertClientAssertionExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
		return ClientAssertionExtensionOutputs.builder()
				// FIXME: convert
				.build();
	}

	private static AuthenticatorAssertionResponse convertResponse(org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse response) throws Base64UrlException, IOException {
		return AuthenticatorAssertionResponse.builder()
				.authenticatorData(convertByteArray(response.getAuthenticatorData()))
				.clientDataJSON(convertByteArray(response.getClientDataJSON()))
				.signature(convertByteArray(response.getSignature()))
				.userHandle(convertByteArray(response.getUserHandle()))
				.build();
	}

	private static com.yubico.webauthn.data.AuthenticatorAssertionResponse convertAssertionResponse(org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse response) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.AuthenticatorAssertionResponse.builder()
				.authenticatorData(convertByteArray(response.getAuthenticatorData()))
				.clientDataJSON(convertByteArray(response.getClientDataJSON()))
				.signature(convertByteArray(response.getSignature()))
				.userHandle(convertByteArray(response.getUserHandle()))
//				.transports() // FIXME:
				.build();
	}

	private static ClientAssertionExtensionOutputs convertAssertionExtension(AuthenticationExtensionsClientOutputs clientExtensionResults) {
		ClientAssertionExtensionOutputs.ClientAssertionExtensionOutputsBuilder result = ClientAssertionExtensionOutputs.builder();
		clientExtensionResults.getOutputs().forEach(output -> {
			registerOutputWithBuilder(output, result);
		});
		return result.build();
	}

	private static void registerOutputWithBuilder(AuthenticationExtensionsClientOutput<?> output, ClientAssertionExtensionOutputs.ClientAssertionExtensionOutputsBuilder result) {
		// FIXME: Process extensions
	}

	// FIXME: Should everything being converted be ByteArray? as in yubico
	static ByteArray convertByteArray(ArrayBuffer arrayBuffer) {
		if (arrayBuffer == null) {
			return null;
		}
		return new ByteArray(arrayBuffer.getBytes());
	}

	// FIXME: Should everything being converted be ByteArray? as in yubico
	static ByteArray convertByteArray(BufferSource bufferSource) {
		if (bufferSource == null) {
			return null;
		}
		return new ByteArray(bufferSource.getBytes());
	}

	private static AssertionRequest convertAssertionRequest(PublicKeyCredentialRequestOptions requestOptions) {
		return AssertionRequest.builder()
				.publicKeyCredentialRequestOptions(convertPublicKeyCredential(requestOptions))
				.build();
	}

	private static com.yubico.webauthn.data.PublicKeyCredentialRequestOptions convertPublicKeyCredential(PublicKeyCredentialRequestOptions requestOptions) {
		return com.yubico.webauthn.data.PublicKeyCredentialRequestOptions.builder()
				.challenge(convertByteArray(requestOptions.getChallenge()))
				.extensions(convertExtensions(requestOptions.getExtensions()))
				.userVerification(convertUserVerivication(requestOptions.getUserVerification()))
				.timeout(requestOptions.getTimeout().toMillis())
				.rpId(requestOptions.getRpId())
				.allowCredentials(convertAllowCredentials(requestOptions.getAllowCredentials()))
				.build();
	}

	private static List<com.yubico.webauthn.data.PublicKeyCredentialDescriptor> convertAllowCredentials(List<PublicKeyCredentialDescriptor> allowCredentials) {
		if (allowCredentials == null) {
			return null;
		}
		if (allowCredentials.isEmpty()) {
			return Collections.emptyList();
		}
		throw new IllegalStateException("TODO: Implement conversion of " + allowCredentials);
	}

	private static com.yubico.webauthn.data.UserVerificationRequirement convertUserVerivication(UserVerificationRequirement userVerification) {
		if (userVerification == null) {
			return null;
		}
		if (UserVerificationRequirement.DISCOURAGED == userVerification) {
			return com.yubico.webauthn.data.UserVerificationRequirement.DISCOURAGED;
		}
		if (UserVerificationRequirement.PREFERRED == userVerification) {
			return com.yubico.webauthn.data.UserVerificationRequirement.PREFERRED;
		}
		if (UserVerificationRequirement.REQUIRED == userVerification) {
			return com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED;
		}
		throw new IllegalStateException("Cannot convert " + userVerification);
	}

	private static AssertionExtensionInputs convertExtensions(AuthenticationExtensionsClientInputs extensions) {
		return AssertionExtensionInputs.builder()
				// FIXME: Need to do the conversions here
				.build();
	}
}
