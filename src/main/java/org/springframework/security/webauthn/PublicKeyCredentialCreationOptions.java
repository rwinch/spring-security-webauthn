package org.springframework.security.webauthn;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;

import java.time.Duration;
import java.util.List;

/**
 * https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PublicKeyCredentialCreationOptions {
	private final PublicKeyCredentialRpEntity rp;

	private final PublicKeyCredentialUserEntity user;

	private final BufferSource challenge;

	private final List<PublicKeyCredentialParameters> pubKeyCredParams;

	private Duration timeout;

	private final List<PublicKeyCredentialDescriptor> excludeCredentials;

	private final AuthenticatorSelectionCriteria authenticatorSelection;

	private String attestation = "none";

	private final AuthenticationExtensionsClientInputs extensions;

	public PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, BufferSource challenge, List<PublicKeyCredentialParameters> pubKeyCredParams, List<PublicKeyCredentialDescriptor> excludeCredentials, AuthenticatorSelectionCriteria authenticatorSelection, AuthenticationExtensionsClientInputs extensions) {
		this.rp = rp;
		this.user = user;
		this.challenge = challenge;
		this.pubKeyCredParams = pubKeyCredParams;
		this.excludeCredentials = excludeCredentials;
		this.authenticatorSelection = authenticatorSelection;
		this.extensions = extensions;
	}

	public PublicKeyCredentialRpEntity getRp() {
		return this.rp;
	}

	public PublicKeyCredentialUserEntity getUser() {
		return this.user;
	}

	public BufferSource getChallenge() {
		return this.challenge;
	}

	public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
		return this.pubKeyCredParams;
	}

	public Duration getTimeout() {
		return this.timeout;
	}

	public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
		return this.excludeCredentials;
	}

	public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
		return this.authenticatorSelection;
	}

	public String getAttestation() {
		return this.attestation;
	}

	public AuthenticationExtensionsClientInputs getExtensions() {
		return this.extensions;
	}

	public static PublicKeyCredentialCreationOptionsBuilder builder() {
		return new PublicKeyCredentialCreationOptionsBuilder();
	}

	public static final class PublicKeyCredentialCreationOptionsBuilder {
		private PublicKeyCredentialRpEntity rp;
		private PublicKeyCredentialUserEntity user;
		private BufferSource challenge;
		private List<PublicKeyCredentialParameters> pubKeyCredParams;
		private Duration timeout;
		private List<PublicKeyCredentialDescriptor> excludeCredentials;
		private AuthenticatorSelectionCriteria authenticatorSelection;
		private String attestation;
		private AuthenticationExtensionsClientInputs extensions;

		private PublicKeyCredentialCreationOptionsBuilder() {
		}

		public static PublicKeyCredentialCreationOptionsBuilder aPublicKeyCredentialCreationOptions() {
			return new PublicKeyCredentialCreationOptionsBuilder();
		}

		public PublicKeyCredentialCreationOptionsBuilder rp(PublicKeyCredentialRpEntity rp) {
			this.rp = rp;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder user(PublicKeyCredentialUserEntity user) {
			this.user = user;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder challenge(BufferSource challenge) {
			this.challenge = challenge;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder pubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) {
			this.pubKeyCredParams = pubKeyCredParams;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder timeout(Duration timeout) {
			this.timeout = timeout;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder excludeCredentials(List<PublicKeyCredentialDescriptor> excludeCredentials) {
			this.excludeCredentials = excludeCredentials;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder authenticatorSelection(AuthenticatorSelectionCriteria authenticatorSelection) {
			this.authenticatorSelection = authenticatorSelection;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder attestation(String attestation) {
			this.attestation = attestation;
			return this;
		}

		public PublicKeyCredentialCreationOptionsBuilder extensions(AuthenticationExtensionsClientInputs extensions) {
			this.extensions = extensions;
			return this;
		}

		public PublicKeyCredentialCreationOptions build() {
			PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(rp, user, challenge, pubKeyCredParams, excludeCredentials, authenticatorSelection, extensions);
			publicKeyCredentialCreationOptions.timeout = this.timeout;
			publicKeyCredentialCreationOptions.attestation = this.attestation;
			return publicKeyCredentialCreationOptions;
		}
	}
}
