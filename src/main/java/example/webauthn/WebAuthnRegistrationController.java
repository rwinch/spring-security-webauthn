package example.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.webauthn.registration.HttpSessionPublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.management.AuthenticationRequest;
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

	private PublicKeyCredentialCreationOptionsRepository repository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

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
	Map<String,String> register(HttpServletRequest request, @RequestBody PublicKeyCredential<AuthenticatorAttestationResponse> credentials) throws Exception {
		WebAuthnRelyingPartyOperations webAuthn = new WebAuthnRelyingPartyOperations();
		PublicKeyCredentialCreationOptions options = this.repository.load(request);
		webAuthn.registerCredential(new RegistrationRequest(options, credentials));
		return Map.of("verified", "true");
	}

	@PostMapping("/webauthn/authenticate")
	@ResponseBody
	Map<String,String> authenticate(@RequestBody PublicKeyCredential<AuthenticatorAttestationResponse> credentials) throws Exception {
		WebAuthnRelyingPartyOperations webAuthn = new WebAuthnRelyingPartyOperations();
		webAuthn.authenticate(new AuthenticationRequest(, credentials));
		return Map.of("verified", "true");
	}
/**
 *
 * {
 *     "id": "AUQ0v-Tk-qYLmYR-ZJny9dRhpEd0HP4IveKtfKVy0L4VhgY9fAlDUIYDWQ3LkYQn5zzAo8wmWqVFMfqiMWrLoJ4",
 *     "rawId": "AUQ0v-Tk-qYLmYR-ZJny9dRhpEd0HP4IveKtfKVy0L4VhgY9fAlDUIYDWQ3LkYQn5zzAo8wmWqVFMfqiMWrLoJ4",
 *     "response": {
 *         "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg",
 *         "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWERjSGw0WHl4NnBXblVfNFdRaDUwTjYxenVEVkRXNGphVHluUjFBWWFTcyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
 *         "signature": "MEYCIQCL0ich_iSd8KmZ_hcWg4aaXD-KA_79NC4M5fOEyQ8BpAIhAPGWxzlk3UAFJSj6lMwJTyvR5u1Yp3NXsl-Oti0b6lNR"
 *     },
 *     "type": "public-key",
 *     "clientExtensionResults": {},
 *     "authenticatorAttachment": "cross-platform"
 * }
 *
 * {"verified":true}
 */
}
