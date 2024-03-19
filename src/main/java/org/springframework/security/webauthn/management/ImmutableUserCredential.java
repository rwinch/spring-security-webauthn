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

import org.springframework.security.webauthn.api.Base64Url;
import org.springframework.security.webauthn.api.BufferSource;
import org.springframework.security.webauthn.api.AuthenticatorTransport;

public class ImmutableUserCredential implements UserCredential {

	private final Base64Url credentialId;

	private final BufferSource userEntityUserId;

	private final PublicKeyCose publicKeyCose;

	private final long signatureCount;

	private final OptionalBoolean backupEligible;

	private final OptionalBoolean backupState;

	private final Instant created;

	private final Instant lastUsed;

	private final String label;

	private final List<AuthenticatorTransport> transports;

	private ImmutableUserCredential(Base64Url credentialId, BufferSource userEntityUserId,
									PublicKeyCose publicKeyCose, long signatureCount,
									OptionalBoolean backupEligible, OptionalBoolean backupState,
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
	public Base64Url getCredentialId() {
		return this.credentialId;
	}

	@Override
	public BufferSource getUserEntityUserId() {
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
	public OptionalBoolean getBackupEligible() {
		return this.backupEligible;
	}

	@Override
	public OptionalBoolean getBackupState() {
		return this.backupState;
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
		if (obj instanceof UserCredential credential) {
			return getCredentialId().equals(credential.getCredentialId());
		}
		return false;
	}

	public static ImmutableUserCredentialBuilder builder() {
		return new ImmutableUserCredentialBuilder();
	}

	public static final class ImmutableUserCredentialBuilder {

		private List<AuthenticatorTransport> transports = new ArrayList<>();
		private Base64Url credentialId;
		private BufferSource userEntityUserId;
		private PublicKeyCose publicKeyCose;
		private long signatureCount;
		private OptionalBoolean backupEligible;
		private OptionalBoolean backupState;
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

		public ImmutableUserCredentialBuilder userEntityUserId(BufferSource userEntityUserId) {
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

		public ImmutableUserCredentialBuilder backupEligible(OptionalBoolean backupEligible) {
			this.backupEligible = backupEligible;
			return this;
		}

		public ImmutableUserCredentialBuilder backupState(OptionalBoolean backupState) {
			this.backupState = backupState;
			return this;
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

		public ImmutableUserCredential build() {
			return new ImmutableUserCredential(this.credentialId, this.userEntityUserId, this.publicKeyCose, this.signatureCount, this.backupEligible, this.backupState, this.created, this.lastUsed, this.label, this.transports);
		}
	}

}
