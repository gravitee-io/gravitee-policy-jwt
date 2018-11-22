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
package io.gravitee.policy.jwt.jwks.rsa;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.policy.jwt.jwks.JWKSourceResolver;
import io.gravitee.policy.jwt.key.PublicKeyHelper;
import io.gravitee.policy.jwt.resolver.SignatureKeyResolver;

import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.CompletableFuture;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RSAJWKSourceResolver<C extends SecurityContext> implements JWKSourceResolver<C> {

    private final JWK jwk;

    private RSAJWKSourceResolver(String publicKey) {
        RSAPublicKey rsaPublicKey = PublicKeyHelper.parsePublicKey(publicKey);
        this.jwk = new RSAKey.Builder(rsaPublicKey).build();
    }

    public RSAJWKSourceResolver(SignatureKeyResolver publicKeyResolver) {
        this(publicKeyResolver.resolve());
    }

    @Override
    public CompletableFuture<JWKSource<C>> resolve() {
        return CompletableFuture.completedFuture(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }
}
