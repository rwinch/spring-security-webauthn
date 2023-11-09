package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.webauthn.api.authentication.AuthenticatorAssertionResponse;
import org.springframework.security.webauthn.api.authentication.PublicKeyCredentialRequestOptions;
import org.springframework.security.webauthn.api.core.ArrayBuffer;
import org.springframework.security.webauthn.api.core.BufferSource;
import org.springframework.security.webauthn.api.registration.*;
import org.springframework.security.webauthn.management.RelyingPartyPublicKey;

public class WebauthnJackson2Module extends SimpleModule {
	public WebauthnJackson2Module() {
		super(WebauthnJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}


	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(ArrayBuffer.class, ArrayBufferMixin.class);
		context.setMixInAnnotations(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixin.class);
		context.setMixInAnnotations(AuthenticationExtensionsClientOutputs.class, AuthenticationExtensionsClientOutputsMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.AuthenticatorAssertionResponseBuilder.class, AuthenticatorAssertionResponseMixin.AuthenticatorAssertionResponseBuilderMixin.class);
		context.setMixInAnnotations(AuthenticatorAssertionResponse.class, AuthenticatorAssertionResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorAttachment.class, AuthenticatorAttachmentMixin.class);
		context.setMixInAnnotations(AuthenticatorAttestationResponse.class, AuthenticatorAttestationResponseMixin.class);
		context.setMixInAnnotations(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixin.class);
		context.setMixInAnnotations(AuthenticatorTransport.class, AuthenticatorTransportMixin.class);
		context.setMixInAnnotations(BufferSource.class, BufferSourceMixin.class);
		context.setMixInAnnotations(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixin.class);
		context.setMixInAnnotations(CredentialPropertiesOutput.class, CredentialPropertiesOutputMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.PublicKeyCredentialBuilder.class, PublicKeyCredentialMixin.PublicKeyCredentialBuilderMixin.class);
		context.setMixInAnnotations(PublicKeyCredential.class, PublicKeyCredentialMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialCreationOptions.class, PublicKeyCredentialCreationOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialRequestOptions.class, PublicKeyCredentialRequestOptionsMixin.class);
		context.setMixInAnnotations(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixin.class);
		context.setMixInAnnotations(RelyingPartyPublicKey.class, RelyingPartyPublicKeyMixin.class);
		context.setMixInAnnotations(ResidentKeyRequirement.class, ResidentKeyRequirementMixin.class);
		context.setMixInAnnotations(UserVerificationRequirement.class, UserVerificationRequirementMixin.class);
	}
}
