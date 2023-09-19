package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;

import java.time.Duration;
import java.util.Base64;

class JacksonTests {
	private ObjectMapper mapper = new ObjectMapper();
	@Test
	void go() throws Exception {
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
}
