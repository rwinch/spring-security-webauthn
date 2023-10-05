package org.springframework.security.webauthn.management;

import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;

public class ImmutableUserCredential implements UserCredential {

	private final ArrayBuffer credentialId;

	private final BufferSource userEntityUserId;

	private final PublicKeyCose publicKeyCose;

	private final long signatureCount;

	private final OptionalBoolean backupEligible;

	private final OptionalBoolean backupState;

	private ImmutableUserCredential(ArrayBuffer credentialId, BufferSource userEntityUserId, PublicKeyCose publicKeyCose, long signatureCount, OptionalBoolean backupEligible, OptionalBoolean backupState) {
		this.credentialId = credentialId;
		this.userEntityUserId = userEntityUserId;
		this.publicKeyCose = publicKeyCose;
		this.signatureCount = signatureCount;
		this.backupEligible = backupEligible;
		this.backupState = backupState;
	}

	@Override
	public ArrayBuffer getCredentialId() {
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
		private ArrayBuffer credentialId;
		private BufferSource userEntityUserId;
		private PublicKeyCose publicKeyCose;
		private long signatureCount;
		private OptionalBoolean backupEligible;
		private OptionalBoolean backupState;

		private ImmutableUserCredentialBuilder() {
		}

		public ImmutableUserCredentialBuilder credentialId(ArrayBuffer credentialId) {
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

		public ImmutableUserCredential build() {
			return new ImmutableUserCredential(this.credentialId, this.userEntityUserId, this.publicKeyCose, this.signatureCount, this.backupEligible, this.backupState);
		}
	}
}
