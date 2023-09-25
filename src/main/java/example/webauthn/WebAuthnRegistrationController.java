package example.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.management.RegistrationRequest;
import org.springframework.security.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class WebAuthnRegistrationController {
	@GetMapping("/webauthn/registration")
	String register() {
		return "registration";
	}

	@GetMapping("/webauthn/authenticate")
	String authenticate() {
		return "authenticate";
	}

	@PostMapping("/webauthn/registration")
	@ResponseBody
	Map<String,String> register(@RequestBody PublicKeyCredential<AuthenticatorAttestationResponse> credentials) throws Exception {
		WebAuthnRelyingPartyOperations webAuthn = new WebAuthnRelyingPartyOperations();
		webAuthn.registerCredential(new RegistrationRequest(webAuthn.createPublicKeyCredentialCreationOptions(null), credentials));
		return Map.of("verified", "true");
	}
}
