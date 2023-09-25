package org.springframework.security.webauthn.management;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;
import org.springframework.security.webauthn.api.registration.AttestationConveyancePreference;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.AuthenticatorSelectionCriteria;
import org.springframework.security.webauthn.api.registration.AuthenticatorTransport;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialParameters;
import org.springframework.security.webauthn.api.registration.ResidentKeyRequirement;

import java.io.IOException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class WebAuthnRelyingPartyOperations {
	PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
			.id("localhost")
			.name("SimpleWebAuthn Example")
			.build();

	// FIXME: Pass in the host, perhaps pass PublicKeyCredentialUserEntity
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		// FIXME: Remove hard coded values
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
//				.userVerification(UserVerificationRequirement.PREFERRED)
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
		PublicKeyCredentialCreationOptions creationOptions = registrationRequest.getCreationOptions();
		PublicKeyCredentialRpEntity creationOptionsRp = creationOptions.getRp();
		RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
				.id(creationOptionsRp.getId())
				.name(creationOptionsRp.getName())
				.build();

		RelyingParty rp = RelyingParty.builder()
				.identity(rpIdentity)
				.credentialRepository(new InMemoryCredentialRepository())
				.origins(Collections.singleton("http://localhost:8080"))
				.build();

		PublicKeyCredentialUserEntity user = creationOptions.getUser();
		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions yubicoOptions = com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.builder()
				.rp(rpIdentity)
				.user(UserIdentity.builder()
						.name(user.getName())
						.displayName(user.getDisplayName())
						.id(new ByteArray(user.getId().getBytes()))
						.build())
				.challenge(new ByteArray(creationOptions.getChallenge().getBytes()))
				.pubKeyCredParams(convertPublicKeyCredential(creationOptions.getPubKeyCredParams()))
				.build();

		try {
			rp.finishRegistration(FinishRegistrationOptions.builder()
					.request(yubicoOptions)
					.response(convertPublicKeyCredential(registrationRequest.getCredential()))
					.build());
			System.out.println("done");
		}
		catch (RegistrationFailedException | Base64UrlException | IOException f) {
			throw new RuntimeException(f);

		}

	}

	private com.yubico.webauthn.data.PublicKeyCredential<com.yubico.webauthn.data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> convertPublicKeyCredential(PublicKeyCredential<AuthenticatorAttestationResponse> credential) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.PublicKeyCredential.<com.yubico.webauthn.data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
				.id(new ByteArray(credential.getRawId().getBytes()))
				.response(convertAttestationResponse(credential.getResponse()))
				.clientExtensionResults(convertClientExtensionResults(credential.getClientExtensionResults()))
				.build();
	}

	private
	ClientRegistrationExtensionOutputs convertClientExtensionResults(AuthenticationExtensionsClientOutputs clientExtensionResults) {
		ClientRegistrationExtensionOutputs.ClientRegistrationExtensionOutputsBuilder result = ClientRegistrationExtensionOutputs.builder();
		clientExtensionResults.getOutputs().forEach(output -> {
			registerOutputWithBuilder(output, result);
		});
		return result.build();
	}

	void registerOutputWithBuilder(AuthenticationExtensionsClientOutput<?> output, ClientRegistrationExtensionOutputs.ClientRegistrationExtensionOutputsBuilder result) {
		if (output instanceof CredentialPropertiesOutput credentialPropertiesOutput) {
			// FIXME: Cannot create the extensions without JSON
			String json = "{ \"rk\": " + credentialPropertiesOutput.getOutput().isRk() + "}";
			ObjectMapper mapper = new ObjectMapper();
			try {
				result.credProps(mapper.readValue(json, Extensions.CredentialProperties.CredentialPropertiesOutput.class));
			} catch(IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	private com.yubico.webauthn.data.AuthenticatorAttestationResponse convertAttestationResponse(AuthenticatorAttestationResponse response) throws Base64UrlException, IOException {
		return com.yubico.webauthn.data.AuthenticatorAttestationResponse.builder()
				.attestationObject(new ByteArray(response.getAttestationObject().getBytes()))
				.clientDataJSON(new ByteArray(response.getClientDataJSON().getBytes()))
				.transports(convertTransports(response.getTransports()))
				.build();
	}

	private Set<com.yubico.webauthn.data.AuthenticatorTransport> convertTransports(List<AuthenticatorTransport> transports) {
		return transports.stream()
				.map(this::convertTransport)
				.collect(Collectors.toSet());
	}

	private com.yubico.webauthn.data.AuthenticatorTransport convertTransport(AuthenticatorTransport authenticatorTransport) {
		return com.yubico.webauthn.data.AuthenticatorTransport.HYBRID;
	}


	private List<com.yubico.webauthn.data.PublicKeyCredentialParameters> convertPublicKeyCredential(List<PublicKeyCredentialParameters> pubKeyCredParams) {
		return pubKeyCredParams.stream()
				.map(this::convertPublicKeyCredential)
				.collect(Collectors.toList());
	}

	private com.yubico.webauthn.data.PublicKeyCredentialParameters convertPublicKeyCredential(PublicKeyCredentialParameters parameters) {
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
