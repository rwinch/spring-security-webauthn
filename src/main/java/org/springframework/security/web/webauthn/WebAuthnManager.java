package org.springframework.security.web.webauthn;


import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.BufferSource;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 *
 *
 * @author Rob Winch
 */
public class WebAuthnManager {
	private SecureRandom random = new SecureRandom();

	private PublicKeyCredentialRpEntity relyingParty = PublicKeyCredentialRpEntity.builder()
			.id("localhost")
			.name("ACME Corporation")
			.build();

	private PublicKeyCredentialUserEntityRepository userEntityRepository = new MapPublicKeyCredentialUserEntityRepository();

//	private ObjectConverter objectConverter = new ObjectConverter();
//	// com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager() returns a com.webauthn4j.WebAuthnManager instance
//	// which doesn't validate an attestation statement. It is recommended configuration for most web application.
//	// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
//	// WebAuthnRegistrationContextValidator and provide validators you like
//	private com.webauthn4j.WebAuthnManager webAuthnManager = com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager(this.objectConverter);


	public WebAuthnManager(PublicKeyCredentialUserEntityRepository authenticators) {
		this.userEntityRepository = authenticators;
	}

	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication) {
		String username = authentication.getName();

		// FIXME: Pass PublicKeyCredentialUserEntity instead of Authentication to avoid lookups in a manager.
		PublicKeyCredentialUserEntity userIdentity = userIdentity(username);
		PublicKeyCredentialCreationOptions result = PublicKeyCredentialCreationOptions.builder()
				.rp(this.relyingParty)
				.user(userIdentity)
				.challenge(new BufferSource(randomBytes()))
				.pubKeyCredParams(Arrays.asList(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256))
				.build();
		return result;
	}

	// FIXME: This should return a registration (should not do any saving in the manager)
	public void register(RegistrationRequest request, Authentication authentication) {
		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions yubicoRequest = convert(request.getCreationOptions());
		RelyingParty rp = RelyingParty.builder()
				.identity(yubicoRequest.getRp())
				.credentialRepository(new InMemoryCredentialRepository())
				.build();
		PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> yubicoResponse = convertToResponse(request);
		FinishRegistrationOptions finishRegistrationOptions = FinishRegistrationOptions.builder()
				.request(yubicoRequest)
				.response(convertToResponse(request))
				.build();
//		com.yubico.webauthn.data.PublicKeyCredentialCreationOptions registration = rp.finishRegistration(finishRegistrationOptions);
//		// Server properties
//		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
//		String rpId = origin.getHost(); //FIXME: This is good for default value, but it should be configurable
//		ServerRegistrationParameters serverRegistrationParameters = request.getParameters();
//		byte[] base64Challenge = serverRegistrationParameters.getChallenge();
//		byte[] attestationObject = request.getResponse().getAttestationObject();
//		byte[] clientDataJSON = request.getResponse().getClientDataJSON();
//		Challenge challenge = new DefaultChallenge(base64Challenge);
//		// FIXME: should populate this
//		byte[] tokenBindingId = null /* set tokenBindingId */;
//		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
//		boolean userVerificationRequired = serverRegistrationParameters.isUserVerificationRequired();
//
//		com.webauthn4j.data.RegistrationRequest registrationRequest = new com.webauthn4j.data.RegistrationRequest(attestationObject, clientDataJSON);
//		com.webauthn4j.data.RegistrationParameters registrationParameters = new com.webauthn4j.data.RegistrationParameters(serverProperty, userVerificationRequired);
//
//		this.webAuthnManager.validate(registrationRequest, registrationParameters);
//
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		// FIXME: should save something w/ a counter on it
//		this.authenticators.save(authentication, request.getResponse());
	}

	private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> convertToResponse(RegistrationRequest request) {
		String clientDataJson = new String(Base64.getDecoder().decode(request.getResponse().getClientDataJSON()));
//		PublicKeyCredential.builder()
//				.id(request.getResponse().)
		return null;
	}

	private com.yubico.webauthn.data.PublicKeyCredentialCreationOptions convert(PublicKeyCredentialCreationOptions options) {
		RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
				.id(options.getRp().getId())  // Set this to a parent domain that covers all subdomains
				// where users' credentials should be valid
				.name(options.getRp().getName())
				.build();
		PublicKeyCredentialUserEntity userEntity = options.getUser();
		UserIdentity user = UserIdentity.builder()
				.name(userEntity.getName())
				.displayName(userEntity.getDisplayName())
				.id(new ByteArray(userEntity.getId().getBytes()))
				.build();
		return com.yubico.webauthn.data.PublicKeyCredentialCreationOptions.builder()
				.rp(rpIdentity)
				.user(user)
				.challenge(new ByteArray(options.getChallenge().getBytes()))
				.pubKeyCredParams(convert(options.getPubKeyCredParams()))
				.build();
	}

	private List<com.yubico.webauthn.data.PublicKeyCredentialParameters> convert(List<PublicKeyCredentialParameters> parameters) {
		return parameters.stream()
			.map(this::convert)
			.collect(Collectors.toList());
	}

	private com.yubico.webauthn.data.PublicKeyCredentialParameters convert(PublicKeyCredentialParameters parameters) {
		return com.yubico.webauthn.data.PublicKeyCredentialParameters.builder()
				.alg(COSEAlgorithmIdentifier.fromId(parameters.getAlg().getRegistryId()).get())
				.build();
	}
//
//	public ServerLoginParameters createLoginParametersFor(Authentication authentication) {
//
//		AuthenticatorAttestationResponse response = this.authenticators.load(authentication);
//		if (response == null) {
//			return null;
//		}
////		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(this.objectConverter);
////		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(this.objectConverter);
////
////		CollectedClientData collectedClientData = collectedClientDataConverter.convert(response.getClientDataJSON());
////		AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());
////
////		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
////		return new AuthenticatorImpl(
////				authenticatorData.getAttestedCredentialData(),
////				attestationObject.getAttestationStatement(),
////				authenticatorData.getSignCount()
////		);
//		return null;
//	}
//
//	// FIXME: login
//
//	public void login(WebAuthnLoginRequest request) {
////		Authenticator authenticator = load(request.getAuthentication());
////		if (authenticator == null) {
////			throw new IllegalStateException("No authenticator found");
////		}
////
////		// Client properties
////
////		// Server properties
////		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
////		String rpId = origin.getHost();
////		Challenge challenge = new DefaultChallenge(request.getLoginParameters().getChallenge());
////		// FIXME: should populate this
////		byte[] tokenBindingId = null /* set tokenBindingId */;
////		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
////		boolean userVerificationRequired = false;
////
////		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
////				request.getCredentialId(),
////				request.getAuthenticatorData(),
////				request.getClientDataJSON(),
////				request.getSignature()
////		);
////		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator, userVerificationRequired);
////
////		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest, authenticationParameters);
////
////		authenticator.setCounter(authenticationData.getAuthenticatorData().getSignCount());
//
//	}
//
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
