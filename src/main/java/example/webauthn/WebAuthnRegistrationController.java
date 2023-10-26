package example.webauthn;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.webauthn.authentication.HttpSessionPublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.registration.HttpSessionPublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsRepository;
import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.registration.AuthenticatorAttestationResponse;
import org.springframework.security.webauthn.api.registration.PublicKeyCredential;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialCreationOptions;
import org.springframework.security.webauthn.api.registration.PublicKeyCredentialUserEntity;
import org.springframework.security.webauthn.management.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.security.Principal;
import java.util.Map;

@Controller
public class WebAuthnRegistrationController {

	final YubicoWebAuthnRelyingPartyOperations rpOptions;

	private final UserDetailsService users;

	private final UserCredentialRepository credentials;

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private PublicKeyCredentialRequestOptionsRepository requestOptionsRepository = new HttpSessionPublicKeyCredentialRequestOptionsRepository();

	public WebAuthnRegistrationController(YubicoWebAuthnRelyingPartyOperations rpOptions, UserDetailsService users, UserCredentialRepository credentials, PublicKeyCredentialUserEntityRepository userEntities) {
		this.rpOptions = rpOptions;
		this.users = users;
		this.credentials = credentials;
		this.userEntities = userEntities;
	}

	@GetMapping("/webauthn/register")
	String register(Map<String, Object> model, Principal principal) {
		PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(principal.getName());
		if (userEntity != null) {
			model.put("credentials", this.credentials.findByUserId(userEntity.getId()));
		}
		return "register";
	}

	@GetMapping("/login/webauthn")
	String authenticate() {
		return "authenticate";
	}

	/**
	 * https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
	 *
	 * {
	 *   "id": "IquGb208Fffq2cROa1ZxMg",
	 *   "rawId": "IquGb208Fffq2cROa1ZxMg",
	 *   "response": {
	 *     "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAECKrhm9tPBX36tnETmtWcTKlAQIDJiABIVggRE8BvWYEIHcoV_Ck5UKFY83l2t3-pyuZ8iB0weG44q0iWCBVML4__WaOLEkHcgsTKbgxjFOyeUndKBpzbu2D0csZ3Q",
	 *     "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSUJRbnVZMVowSzFIcUJvRldDcDJ4bEpsOC1vcV9hRklYenlUX0YwLTBHVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
	 *     "transports": [
	 *       "hybrid",
	 *       "internal"
	 *     ],
	 *     "publicKeyAlgorithm": -7,
	 *     "publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERE8BvWYEIHcoV_Ck5UKFY83l2t3-pyuZ8iB0weG44q1VML4__WaOLEkHcgsTKbgxjFOyeUndKBpzbu2D0csZ3Q",
	 *     "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAECKrhm9tPBX36tnETmtWcTKlAQIDJiABIVggRE8BvWYEIHcoV_Ck5UKFY83l2t3-pyuZ8iB0weG44q0iWCBVML4__WaOLEkHcgsTKbgxjFOyeUndKBpzbu2D0csZ3Q"
	 *   },
	 *   "type": "public-key",
	 *   "clientExtensionResults": {
	 *     "credProps": {
	 *       "rk": true
	 *     }
	 *   },
	 *   "authenticatorAttachment": "cross-platform"
	 * }
	 *
	 * @param request
	 * @param credentials
	 * @return
	 * @throws Exception
	 */
//	@PostMapping("/webauthn/registration")
//	@ResponseBody
//	Map<String,String> register(HttpServletRequest request, @RequestBody PublicKeyCredential<AuthenticatorAttestationResponse> credentials) throws Exception {
//		PublicKeyCredentialCreationOptions options = this.creationOptionsRepository.load(request);
//		this.rpOptions.registerCredential(new RelyingPartyRegistrationRequest(options, credentials));
//		return Map.of("verified", "true");
//	}

	/**
	 * {
	 *   "id": "pfrNc66auLPxKVb82iQoRg",
	 *   "rawId": "pfrNc66auLPxKVb82iQoRg",
	 *   "response": {
	 *     "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
	 *     "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaEpzR1c3amFfbEkxNHpZdWVSYUx1dDZ5M0thVEhJYjVHcFJ4WlEwckFJUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
	 *     "signature": "MEUCIQDpMpIB53Nx_rtuN3GIxDHxTlZJ7FnS1oJ7z3jbDY3FigIgF-aXxjbMqjtip6vf4uJRx6y3Xx7nZ4rVGXi_PoBfcJg",
	 *     "userHandle": "+��\u0011���\u0018\u0005DFj;2�C\u000e�!J�\u0015�Qm�(��\u0018�4"
	 *   },
	 *   "type": "public-key",
	 *   "clientExtensionResults": {},
	 *   "authenticatorAttachment": "cross-platform"
	 * }
	 *
	 * {
	 *   "id": "IquGb208Fffq2cROa1ZxMg",
	 *   "rawId": "IquGb208Fffq2cROa1ZxMg",
	 *   "response": {
	 *     "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
	 *     "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaDB2Z3dHUWpvQ3pBekRVc216UHBrLUpWSUpSUmduMEw0S1ZTWU5SY0VaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
	 *     "signature": "MEUCIAdfzPAn3voyXynwa0IXk1S0envMY5KP3NEe9aj4B2BuAiEAm_KJhQoWXdvfhbzwACU3NM4ltQe7_Il46qFUwtpuTdg",
	 *     "userHandle": "oWJtkJ6vJ_m5b84LB4_K7QKTCTEwLIjCh4tFMCGHO4w"
	 *   },
	 *   "type": "public-key",
	 *   "clientExtensionResults": {},
	 *   "authenticatorAttachment": "cross-platform"
	 * }
	 *
	 * @param credentials
	 * @return
	 * @throws Exception
	 */
//	@PostMapping("/login/webauthn")
//	@ResponseBody
	Map<String,String> authenticate(HttpServletRequest request, HttpServletResponse response, @RequestBody PublicKeyCredential<AuthenticatorAssertionResponse> publicKey) throws Exception {
		PublicKeyCredentialRequestOptions requestOptions = this.requestOptionsRepository.load(request);
		String username = this.rpOptions.authenticate(new AuthenticationRequest(requestOptions, publicKey));
		UserDetails userDetails = this.users.loadUserByUsername(username);
		UsernamePasswordAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
		SecurityContext newContext = SecurityContextHolder.createEmptyContext();
		newContext.setAuthentication(authenticated);
		SecurityContextHolder.setContext(newContext);

		new HttpSessionSecurityContextRepository().saveContext(newContext, request, response);
		System.out.println(username);
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
