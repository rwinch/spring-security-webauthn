package example.webauthn.security;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.AuthenticatorAttestationResponse;
import org.springframework.stereotype.Component;

/**
 * FIXME: This should be saved per Authentication
 *
 * @author Rob Winch
 */
public class WebAuthnAuthenticatorRepository {
	private AuthenticatorAttestationResponse response;

	public void save(Authentication authentication, AuthenticatorAttestationResponse response) {
		this.response = response;
	}

	public Authenticator load(Authentication authentication) {
		if (response == null) {
			return null;
		}
		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(new JsonConverter());
		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(new CborConverter());

		CollectedClientData collectedClientData = collectedClientDataConverter.convert(response.getClientDataJSON());
		AttestationObject attestationObject = attestationObjectConverter.convert(response.getAttestationObject());

		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject.getAuthenticatorData();
		return new AuthenticatorImpl(
						authenticatorData.getAttestedCredentialData(),
						attestationObject.getAttestationStatement(),
						authenticatorData.getSignCount()
				);
	}
}
