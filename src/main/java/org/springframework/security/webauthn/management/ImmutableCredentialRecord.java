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

package org.springframework.security.webauthn.management;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.AuthenticatorTransport;
import org.springframework.security.webauthn.api.PublicKeyCredentialType;

public class ImmutableCredentialRecord implements CredentialRecord {

	private final Base64Url credentialId;

	private final Base64Url userEntityUserId;

	private final PublicKeyCose publicKeyCose;

	private final long signatureCount;

	private final boolean backupEligible;

	private final boolean backupState;

	private final boolean uvInitialized;

	private final Instant created;

	private final Instant lastUsed;

	private final String label;

	private final List<AuthenticatorTransport> transports;

	private ImmutableCredentialRecord(Base64Url credentialId, Base64Url userEntityUserId,
									  PublicKeyCose publicKeyCose, long signatureCount,
									  Optional<Boolean> backupEligible, Optional<Boolean> backupState,
									  Instant created,
									  Instant lastUsed,
									  String label,
									  List<AuthenticatorTransport> transports) {
		this.credentialId = credentialId;
		this.userEntityUserId = userEntityUserId;
		this.publicKeyCose = publicKeyCose;
		this.signatureCount = signatureCount;
		this.backupEligible = backupEligible;
		this.backupState = backupState;
		this.created = created;
		this.lastUsed = lastUsed;
		this.label = label;
		this.transports = transports;
	}

	@Override
	public PublicKeyCredentialType getType() {
		return PublicKeyCredentialType.PUBLIC_KEY;
	}

	@Override
	public Base64Url getCredentialId() {
		return this.credentialId;
	}

	@Override
	public Base64Url getUserEntityUserId() {
		return this.userEntityUserId;
	}

	@Override
	public PublicKeyCose getPublicKeyCose() {
		return this.publicKeyCose;
	}

	@Override
	public long getSignatureCount() {
		return this.signatureCount;
	}


	@Override
	public List<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	public Instant getCreated() {
		return created;
	}

	public Instant getLastUsed() {
		return lastUsed;
	}

	public String getLabel() {
		return label;
	}

	@Override
	public int hashCode() {
		return this.credentialId.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CredentialRecord credential) {
			return getCredentialId().equals(credential.getCredentialId());
		}
		return false;
	}

	public static ImmutableUserCredentialBuilder builder() {
		return new ImmutableUserCredentialBuilder();
	}

	public static ImmutableUserCredentialBuilder fromUserCredential(CredentialRecord credentialRecord) {
		return builder()
				.credentialId(credentialRecord.getCredentialId())
				.userEntityUserId(credentialRecord.getUserEntityUserId())
				.publicKeyCose(credentialRecord.getPublicKeyCose())
				.signatureCount(credentialRecord.getSignatureCount())
				.backupEligible(credentialRecord.getBackupEligible())
				.backupState(credentialRecord.getBackupState())
				.created(credentialRecord.getCreated())
				.lastUsed(credentialRecord.getLastUsed())
				.label(credentialRecord.getLabel())
				.transports(credentialRecord.getTransports());
	}

	public static final class ImmutableUserCredentialBuilder {

		private List<AuthenticatorTransport> transports = new ArrayList<>();
		private Base64Url credentialId;
		private Base64Url userEntityUserId;
		private PublicKeyCose publicKeyCose;
		private long signatureCount;
		private Optional<Boolean> backupEligible = Optional.empty();
		private Optional<Boolean> backupState = Optional.empty();
		private Instant created = Instant.now();
		private Instant lastUsed = Instant.now();
		private String label;

		private ImmutableUserCredentialBuilder() {
		}

		public ImmutableUserCredentialBuilder transports(List<AuthenticatorTransport> transports) {
			this.transports = transports;
			return this;
		}

		public ImmutableUserCredentialBuilder transports(AuthenticatorTransport... transports) {
			return transports(Arrays.asList(transports));
		}

		public ImmutableUserCredentialBuilder credentialId(Base64Url credentialId) {
			this.credentialId = credentialId;
			return this;
		}

		public ImmutableUserCredentialBuilder userEntityUserId(Base64Url userEntityUserId) {
			this.userEntityUserId = userEntityUserId;
			return this;
		}

		public ImmutableUserCredentialBuilder publicKeyCose(PublicKeyCose publicKeyCose) {
			this.publicKeyCose = publicKeyCose;
			return this;
		}

		public ImmutableUserCredentialBuilder signatureCount(long signatureCount) {
			this.signatureCount = signatureCount;
			return this;
		}

		public ImmutableUserCredentialBuilder backupEligible(Optional<Boolean> backupEligible) {
			this.backupEligible = backupEligible;
			return this;
		}

		public ImmutableUserCredentialBuilder backupEligible(boolean backupEligible) {
			return backupEligible(Optional.of(backupEligible));
		}

		public ImmutableUserCredentialBuilder backupState(Optional<Boolean> backupState) {
			this.backupState = backupState;
			return this;
		}

		public ImmutableUserCredentialBuilder backupState(boolean backupState) {
			return backupState(Optional.of(backupState));
		}

		public ImmutableUserCredentialBuilder created(Instant created) {
			this.created = created;
			return this;
		}

		public ImmutableUserCredentialBuilder lastUsed(Instant lastUsed) {
			this.lastUsed = lastUsed;
			return this;
		}

		public ImmutableUserCredentialBuilder label(String label) {
			this.label = label;
			return this;
		}

		public ImmutableCredentialRecord build() {
			return new ImmutableCredentialRecord(this.credentialId, this.userEntityUserId, this.publicKeyCose, this.signatureCount, this.backupEligible, this.backupState, this.created, this.lastUsed, this.label, this.transports);
		}
	}

}
