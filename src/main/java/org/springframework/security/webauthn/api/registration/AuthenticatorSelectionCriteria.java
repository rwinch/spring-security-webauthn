package org.springframework.security.webauthn.api.registration;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticatorSelectionCriteria {
	private final AuthenticatorAttachment authenticatorAttachment;

	private final ResidentKeyRequirement residentKey;

	private final UserVerificationRequirement userVerification;

	public AuthenticatorSelectionCriteria(AuthenticatorAttachment authenticatorAttachment, ResidentKeyRequirement residentKey, UserVerificationRequirement userVerification) {
		this.authenticatorAttachment = authenticatorAttachment;
		this.residentKey = residentKey;
		this.userVerification = userVerification;
	}

	public AuthenticatorAttachment getAuthenticatorAttachment() {
		return this.authenticatorAttachment;
	}

	public ResidentKeyRequirement getResidentKey() {
		return this.residentKey;
	}

	public UserVerificationRequirement getUserVerification() {
		return this.userVerification;
	}

	// FIXME: Do we need this for legacy or is it breaking the fmt
//	public boolean isRequireResidentKey() {
//		return ResidentKeyRequirement.REQUIRED.equals(getResidentKey());
//	}

	public static AuthenticatorSelectionCriteriaBuilder builder() {
		return new AuthenticatorSelectionCriteriaBuilder();
	}

	public static final class AuthenticatorSelectionCriteriaBuilder {
		private AuthenticatorAttachment authenticatorAttachment;
		private ResidentKeyRequirement residentKey;
		private UserVerificationRequirement userVerification;

		private AuthenticatorSelectionCriteriaBuilder() {
		}

		public static AuthenticatorSelectionCriteriaBuilder anAuthenticatorSelectionCriteria() {
			return new AuthenticatorSelectionCriteriaBuilder();
		}

		public AuthenticatorSelectionCriteriaBuilder authenticatorAttachment(AuthenticatorAttachment authenticatorAttachment) {
			this.authenticatorAttachment = authenticatorAttachment;
			return this;
		}

		public AuthenticatorSelectionCriteriaBuilder residentKey(ResidentKeyRequirement residentKey) {
			this.residentKey = residentKey;
			return this;
		}

		public AuthenticatorSelectionCriteriaBuilder userVerification(UserVerificationRequirement userVerification) {
			this.userVerification = userVerification;
			return this;
		}

		public AuthenticatorSelectionCriteria build() {
			return new AuthenticatorSelectionCriteria(this.authenticatorAttachment, this.residentKey, this.userVerification);
		}
	}
}
