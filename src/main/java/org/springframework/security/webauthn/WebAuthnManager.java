package org.springframework.security.webauthn;

import org.springframework.security.core.Authentication;

public interface WebAuthnManager {
	PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(Authentication authentication);
}
