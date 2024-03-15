
/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.webauthn.api;

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
