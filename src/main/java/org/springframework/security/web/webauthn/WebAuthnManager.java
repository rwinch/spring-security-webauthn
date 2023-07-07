package org.springframework.security.web.webauthn;

//import com.webauthn4j.authenticator.Authenticator;
//import com.webauthn4j.authenticator.AuthenticatorImpl;
//import com.webauthn4j.converter.AttestationObjectConverter;
//import com.webauthn4j.converter.CollectedClientDataConverter;
//import com.webauthn4j.converter.util.ObjectConverter;
//import com.webauthn4j.data.AuthenticationData;
//import com.webauthn4j.data.AuthenticationParameters;
//import com.webauthn4j.data.AuthenticationRequest;
//import com.webauthn4j.data.attestation.AttestationObject;
//import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
//import com.webauthn4j.data.client.CollectedClientData;
//import com.webauthn4j.data.client.Origin;
//import com.webauthn4j.data.client.challenge.Challenge;
//import com.webauthn4j.data.client.challenge.DefaultChallenge;
//import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
//import com.webauthn4j.server.ServerProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import example.webauthn.security.WebAuthnAuthenticatorRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 *
 * @author Rob Winch
 */
public class WebAuthnManager {
	private SecureRandom random = new SecureRandom();

//	private ObjectConverter objectConverter = new ObjectConverter();
//	// com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager() returns a com.webauthn4j.WebAuthnManager instance
//	// which doesn't validate an attestation statement. It is recommended configuration for most web application.
//	// If you are building enterprise web application and need to validate the attestation statement, use the constructor of
//	// WebAuthnRegistrationContextValidator and provide validators you like
//	private com.webauthn4j.WebAuthnManager webAuthnManager = com.webauthn4j.WebAuthnManager.createNonStrictWebAuthnManager(this.objectConverter);

	private Map<String, byte[]> usernameToUserId = new ConcurrentHashMap<>();

	private final WebAuthnAuthenticatorRepository authenticators;

	// FIXME this should be stored in a repository
	private PublicKeyCredentialCreationOptions pkCredentialOptions;

	public WebAuthnManager(WebAuthnAuthenticatorRepository authenticators) {
		this.authenticators = authenticators;
	}

	public ServerRegistrationParameters createRegistrationParametersFor(Authentication authentication) {
		ServerRegistrationParameters result = new ServerRegistrationParameters();
		result.setChallenge(randomBytes());
		result.setUserId(userId(authentication));
		return result;
	}

	// FIXME: This should return a registration (should not do any saving in the manager)
	public void register(RegistrationRequest request) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // FIXME add as argument to method or use strategy
		RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
				.id(request.getOrigin().toExternalForm())  // Set this to a parent domain that covers all subdomains
				// where users' credentials should be valid
				.name("Example Application")
				.build();

		RelyingParty rp = RelyingParty.builder()
				.identity(rpIdentity)
				.credentialRepository(new InMemoryCredentialRepository())
				.build();

		this.pkCredentialOptions = rp.startRegistration(
				StartRegistrationOptions.builder()
						.user(
								UserIdentity.builder()
										.name("alice")
										.displayName("Alice Hypothetical")
										.id(new ByteArray(getUserHandle(authentication.getName())))
										.build()
						)
						.build());
		try {
			String credentialsCreateJson = this.pkCredentialOptions.toCredentialsCreateJson();
			System.out.println(credentialsCreateJson);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
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
		this.authenticators.save(authentication, request.getResponse());
	}

	public ServerLoginParameters createLoginParametersFor(Authentication authentication) {

		AuthenticatorAttestationResponse response = this.authenticators.load(authentication);
		if (response == null) {
			return null;
		}
//		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(this.objectConverter);
//		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(this.objectConverter);
//
//		CollectedClientData collectedClientData = collectedClientDataConverter.convert(response.getClientDataJSON());
//		AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());
//
//		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
//		return new AuthenticatorImpl(
//				authenticatorData.getAttestedCredentialData(),
//				attestationObject.getAttestationStatement(),
//				authenticatorData.getSignCount()
//		);
		return null;
	}

	// FIXME: login

	public void login(WebAuthnLoginRequest request) {
//		Authenticator authenticator = load(request.getAuthentication());
//		if (authenticator == null) {
//			throw new IllegalStateException("No authenticator found");
//		}
//
//		// Client properties
//
//		// Server properties
//		Origin origin = new Origin(request.getOrigin().toExternalForm()); /* set origin */;
//		String rpId = origin.getHost();
//		Challenge challenge = new DefaultChallenge(request.getLoginParameters().getChallenge());
//		// FIXME: should populate this
//		byte[] tokenBindingId = null /* set tokenBindingId */;
//		ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
//		boolean userVerificationRequired = false;
//
//		AuthenticationRequest authenticationRequest = new AuthenticationRequest(
//				request.getCredentialId(),
//				request.getAuthenticatorData(),
//				request.getClientDataJSON(),
//				request.getSignature()
//		);
//		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator, userVerificationRequired);
//
//		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest, authenticationParameters);
//
//		authenticator.setCounter(authenticationData.getAuthenticatorData().getSignCount());

	}

	private byte[] userId(Authentication authentication) {
		if (authentication == null) {
			return randomBytes();
		}
		String username = authentication.getName();
		return this.usernameToUserId.computeIfAbsent(username, u -> randomBytes());
	}

	private byte[] randomBytes() {
		byte[] result = new byte[64];
		this.random.nextBytes(result);
		return result;
	}

	private byte[] getUserHandle(String username) {
		final byte[] existingHandle = this.usernameToUserId.get(username);
		if (existingHandle != null) {
			return existingHandle;
		}
		byte[] newHandle = new byte[64];
		this.random.nextBytes(newHandle);
		this.usernameToUserId.put(username, newHandle);
		return newHandle;
	}
}
