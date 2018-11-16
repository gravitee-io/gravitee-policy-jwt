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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.gravitee.policy.jwt.jwks.JWKSourceResolver;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public abstract class AbstractKeyProcessor implements KeyProcessor {

    private final JWKSourceResolver jwkSourceResolver;

    private final static DefaultJWTClaimsVerifier claimsVerifier = new DefaultJWTClaimsVerifier();
    static {
        claimsVerifier.setMaxClockSkew(0);
    }

    protected AbstractKeyProcessor(JWKSourceResolver jwkSourceResolver) {
        this.jwkSourceResolver = jwkSourceResolver;
    }

    @Override
    public JWTClaimsSet process(String token) throws Exception {
        JWKSource jwkSource = jwkSourceResolver.resolve();

        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);

        jwtProcessor.setJWSKeySelector(keySelector(jwkSource));

        SecurityContext ctx = null; // optional context parameter, not required here
        return jwtProcessor.process(token, ctx);
    }

    abstract JWSKeySelector keySelector(JWKSource jwkSource);
}
