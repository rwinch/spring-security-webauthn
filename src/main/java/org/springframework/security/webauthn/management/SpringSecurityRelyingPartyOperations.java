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

import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.core.ResolvableType;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.*;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SpringSecurityRelyingPartyOperations implements WebAuthnRelyingPartyOperations {

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	private final Set<String> allowedOrigins;

	private final PublicKeyCredentialRpEntity rp;

	public SpringSecurityRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities, UserCredentialRepository userCredentials, PublicKeyCredentialRpEntity rpEntity, Set<String> allowedOrigins) {
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
		this.rp = rpEntity;
		this.allowedOrigins = allowedOrigins;
	}

	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {

		// FIXME: Remove hard coded values
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
//				.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM) // specifying this just limits to either platform or cross platform
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.REQUIRED) // REQUIRED
				.build();


		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<CredentialRecord> credentialRecords = this.userCredentials.findByUserId(userEntity.getId());
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
				.excludeCredentials(convertCredentials(credentialRecords))
				.timeout(Duration.ofMinutes(10))
				.build();
		return options;
	}


	private List<PublicKeyCredentialDescriptor> convertCredentials(List<CredentialRecord> credentialRecords) {
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
		PublicKeyCredentialCreationOptions options = rpRegistrationRequest.getCreationOptions();
		PublicKeyCredential<AuthenticatorAttestationResponse> credential = rpRegistrationRequest.getPublicKey().getCredential();
		AuthenticatorAttestationResponse response = credential.getResponse();
		AuthenticationExtensionsClientOutputs clientExtensionResults = credential.getClientExtensionResults();
		byte[] jsonText = response.getClientDataJSON().getBytes();
		ResolvableType resolvableType = ResolvableType.forClassWithGenerics(Map.class, String.class, String.class);
		JsonMapper json = JsonMapper
				.builder()
				.findAndAddModules()
				.build();

		return null;
	}


	@Override
	public PublicKeyCredentialRequestOptions createCredentialRequestOptions(Authentication authentication) {
		return null;
	}

	@Override
	public String authenticate(AuthenticationRequest request) {
		return "";
	}
}
