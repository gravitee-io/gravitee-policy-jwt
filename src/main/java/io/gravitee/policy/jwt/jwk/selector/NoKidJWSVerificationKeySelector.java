/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.jwt.jwk.selector;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Set;

/**
 * Specific implementation of {@link JWSKeySelector} that disable matching of kid and allows matching JWT with a given key that does not define key id.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class NoKidJWSVerificationKeySelector<C extends SecurityContext> extends JWSVerificationKeySelector<C> {

    public NoKidJWSVerificationKeySelector(JWSAlgorithm jwsAlg, JWKSource<C> jwkSource) {
        super(jwsAlg, jwkSource);
    }

    @Override
    protected JWKMatcher createJWKMatcher(JWSHeader jwsHeader) {
        if (!isAllowed(jwsHeader.getAlgorithm())) {
            // Unexpected JWS alg
            return null;
        }

        // Copied from JWKMatcher.forJWSHeader(JWSHeader) with kid removal.
        JWSAlgorithm algorithm = jwsHeader.getAlgorithm();
        if (JWSAlgorithm.Family.RSA.contains(algorithm) || JWSAlgorithm.Family.EC.contains(algorithm)) {
            // RSA or EC key matcher
            return new JWKMatcher.Builder()
                .keyType(KeyType.forAlgorithm(algorithm))
                .keyUses(KeyUse.SIGNATURE, null)
                .algorithms(algorithm, null)
                .x509CertSHA256Thumbprint(jwsHeader.getX509CertSHA256Thumbprint())
                .build();
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
            // HMAC secret matcher
            return new JWKMatcher.Builder().keyType(KeyType.forAlgorithm(algorithm)).privateOnly(true).algorithms(algorithm, null).build();
        } else if (JWSAlgorithm.Family.ED.contains(algorithm)) {
            return new JWKMatcher.Builder()
                .keyType(KeyType.forAlgorithm(algorithm))
                .keyUses(KeyUse.SIGNATURE, null)
                .algorithms(algorithm, null)
                .curves(Curve.forJWSAlgorithm(algorithm))
                .build();
        } else {
            return null; // Unsupported algorithm
        }
    }
}
