/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.jwt.processor;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.policy.jwt.jwks.JWKSourceResolver;

import java.util.Collections;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class PublicKeyKeyProcessor<C extends SecurityContext> extends AbstractKeyProcessor<C> {

    public PublicKeyKeyProcessor(JWKSourceResolver<C> jwkSourceResolver) {
        super(jwkSourceResolver);
    }

    @Override
    JWSKeySelector<C> jwsKeySelector(JWKSource<C> jwkSource) {
        return (header, context) -> {
            try {
                return Collections.singletonList(((RSAKey) ((ImmutableJWKSet) jwkSource).getJWKSet().getKeys().get(0)).toPublicKey());
            } catch (JOSEException e) {
                return null;
            }
        };
    }
}
