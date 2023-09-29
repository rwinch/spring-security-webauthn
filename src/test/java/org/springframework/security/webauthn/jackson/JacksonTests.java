package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;

import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JacksonTests {
	private ObjectMapper mapper = new ObjectMapper();
	@Test
	void writePublicKeyCredentialCreationOptions() throws Exception {
		String expected = """
				{
				    "attestation": "none",
				    "authenticatorSelection": {
				        "requireResidentKey": false,
				        "residentKey": "discouraged"
				    },
				    "challenge": "IBQnuY1Z0K1HqBoFWCp2xlJl8-oq_aFIXzyT_F0-0GU",
				    "excludeCredentials": [],
				    "extensions": {
				        "credProps": true
				    },
				    "pubKeyCredParams": [
				        {
				            "alg": -7,
				            "type": "public-key"
				        },
				        {
				            "alg": -257,
				            "type": "public-key"
				        }
				    ],
				    "rp": {
				        "id": "localhost",
				        "name": "SimpleWebAuthn Example"
				    },
				    "timeout": 60000,
				    "user": {
				        "displayName": "user@localhost",
				        "id": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w",
				        "name": "user@localhost"
				    }
				}
				""";

		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.PREFERRED)
				.residentKey(ResidentKeyRequirement.DISCOURAGED)
				.build();
		BufferSource challenge = BufferSource.fromBase64("IBQnuY1Z0K1HqBoFWCp2xlJl8-oq_aFIXzyT_F0-0GU");
		PublicKeyCredentialRpEntity rp = PublicKeyCredentialRpEntity.builder()
				.id("localhost")
				.name("SimpleWebAuthn Example")
				.build();
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
				.pubKeyCredParams(PublicKeyCredentialParameters.RS256, PublicKeyCredentialParameters.ES256)
				.authenticatorSelection(authenticatorSelection)
				.challenge(challenge)
				.rp(rp)
				.extensions(clientInputs)
				.timeout(Duration.ofMillis(60000))
				.build();

		String string = this.mapper.writeValueAsString(options);

		System.out.println(string);

		JSONAssert.assertEquals(expected, string, false);
	}

	@Test
	void readPublicKeyCredentialAuthenticatorAttestationResponse() throws Exception {
		String json = """
			{
			   "id": "AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM",
			   "rawId": "AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM",
			   "response": {
				 "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk",
				 "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				 "transports": [
				   "hybrid",
				   "internal"
				 ],
				 "publicKeyAlgorithm": -7,
				 "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkr7Z6k8TDS6Mc36C9WnYend5_wLNTfOrA7nKXHwvY6wrnHk6VMYQ_EtL7zlMAAG6bhqpUrgJJYnstgN2SO4EuQ",
				 "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"
			   },
			   "type": "public-key",
			   "clientExtensionResults": {
				 "credProps": {
				   "rk": false
				 }
			   },
			   "authenticatorAttachment": "cross-platform"
			 }
		""";
		PublicKeyCredential<AuthenticatorAttestationResponse> publicKeyCredential = this.mapper.readValue(json, new TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse>>() {
		});

		DefaultAuthenticationExtensionsClientOutputs clientExtensionResults = new DefaultAuthenticationExtensionsClientOutputs();
		clientExtensionResults.add(new CredentialPropertiesOutput(false));

		PublicKeyCredential<AuthenticatorAttestationResponse> expected = PublicKeyCredential.builder()
				.id("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM")
				.rawId(ArrayBuffer.fromBase64("AX6nVVERrH6opMafUGn3Z9EyNEy6cftfBKV_2YxYl1jdW8CSJxMKGXFV3bnrKTiMSJeInkG7C6B2lPt8E5i3KaM"))
				.response(AuthenticatorAttestationResponse.builder()
						.attestationObject(ArrayBuffer.fromBase64("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjFSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
						.clientDataJSON(ArrayBuffer.fromBase64("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
						.transports(AuthenticatorTransport.HYBRID, AuthenticatorTransport.INTERNAL)
						.publicKeyAlgorithm(COSEAlgorithmIdentifier.ES256)
						.publicKey(ArrayBuffer.fromBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkr7Z6k8TDS6Mc36C9WnYend5_wLNTfOrA7nKXHwvY6wrnHk6VMYQ_EtL7zlMAAG6bhqpUrgJJYnstgN2SO4EuQ"))
						.authenticatorData(ArrayBuffer.fromBase64("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAQQF-p1VREax-qKTGn1Bp92fRMjRMunH7XwSlf9mMWJdY3VvAkicTChlxVd256yk4jEiXiJ5BuwugdpT7fBOYtymjpQECAyYgASFYIJK-2epPEw0ujHN-gvVp2Hp3ef8CzU3zqwO5ylx8L2OsIlggK5x5OlTGEPxLS-85TAABum4aqVK4CSWJ7LYDdkjuBLk"))
						.build())
				.type(PublicKeyCredentialType.PUBLIC_KEY)
				.clientExtensionResults(clientExtensionResults)
				.build();

		assertThat(publicKeyCredential).usingRecursiveComparison().isEqualTo(expected);
	}


	@Test
	void writeAuthenticationOptions() throws Exception {
		WebAuthnRelyingPartyOperations relyingPartyOperations = new WebAuthnRelyingPartyOperations();
		PublicKeyCredentialRequestOptions credentialRequestOptions = PublicKeyCredentialRequestOptions.builder()
				.allowCredentials(Arrays.asList())
				.challenge(BufferSource.fromBase64("I69THX904Q8ONhCgUgOu2PCQCcEjTDiNmokdbgsAsYU"))
				.rpId("localhost")
				.timeout(Duration.ofMinutes(5))
				.userVerification(UserVerificationRequirement.REQUIRED)
				.build();
		String actual = this.mapper.writeValueAsString(credentialRequestOptions);

		String expected = """
		{
    "challenge": "I69THX904Q8ONhCgUgOu2PCQCcEjTDiNmokdbgsAsYU",
    "allowCredentials": [],
    "timeout": 300000,
    "userVerification": "required",
    "rpId": "localhost"
  }
  
""";
		JSONAssert.assertEquals(expected, actual, false);
	}


	@Test
	void readPublicKeyCredentialAuthenticatorAssertionResponse() throws Exception {
		String json = """
			{
			   "id": "IquGb208Fffq2cROa1ZxMg",
			   "rawId": "IquGb208Fffq2cROa1ZxMg",
			   "response": {
				 "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
				 "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaDB2Z3dHUWpvQ3pBekRVc216UHBrLUpWSUpSUmduMEw0S1ZTWU5SY0VaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
				 "signature": "MEUCIAdfzPAn3voyXynwa0IXk1S0envMY5KP3NEe9aj4B2BuAiEAm_KJhQoWXdvfhbzwACU3NM4ltQe7_Il46qFUwtpuTdg",
				 "userHandle": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"
			   },
			   "type": "public-key",
			   "clientExtensionResults": {},
			   "authenticatorAttachment": "cross-platform"
			 }
		""";
		PublicKeyCredential<AuthenticatorAssertionResponse> publicKeyCredential = this.mapper.readValue(json, new TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse>>() {
		});

		DefaultAuthenticationExtensionsClientOutputs clientExtensionResults = new DefaultAuthenticationExtensionsClientOutputs();

		PublicKeyCredential<AuthenticatorAssertionResponse> expected = PublicKeyCredential.builder()
				.id("IquGb208Fffq2cROa1ZxMg")
				.rawId(ArrayBuffer.fromBase64("IquGb208Fffq2cROa1ZxMg"))
				.response(AuthenticatorAssertionResponse.builder()
						.authenticatorData(ArrayBuffer.fromBase64("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA"))
						.clientDataJSON(ArrayBuffer.fromBase64("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaDB2Z3dHUWpvQ3pBekRVc216UHBrLUpWSUpSUmduMEw0S1ZTWU5SY0VaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"))
						.signature(ArrayBuffer.fromBase64("MEUCIAdfzPAn3voyXynwa0IXk1S0envMY5KP3NEe9aj4B2BuAiEAm_KJhQoWXdvfhbzwACU3NM4ltQe7_Il46qFUwtpuTdg"))
						.userHandle(ArrayBuffer.fromBase64("oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"))
						.build())
				.type(PublicKeyCredentialType.PUBLIC_KEY)
				.clientExtensionResults(clientExtensionResults)
				.authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
				.build();

		assertThat(publicKeyCredential).usingRecursiveComparison().isEqualTo(expected);
	}
}
