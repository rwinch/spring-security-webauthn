package org.springframework.security.webauthn.jackson;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = COSEAlgorithmIdentifierSerializer.class)
@JsonDeserialize(using = COSEAlgorithmIdentifierDeserializer.class)
abstract class COSEAlgorithmIdentifierMixin {
}
