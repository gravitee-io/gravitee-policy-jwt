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
package io.gravitee.policy.v3.jwt.processor;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.policy.jwt.alg.Signature;
import java.security.Key;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.SecretKey;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Deprecated
public class NoAlgorithmRSAKeyProcessor<C extends SecurityContext> extends AbstractKeyProcessor<C> {

    @Override
    JWSKeySelector<C> jwsKeySelector(JWKSource<C> jwkSource, Signature signature) {
        return new JWSVerificationKeySelector<C>(Signature.RSA_RS256.getAlg(), jwkSource) {
            @Override
            protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {
                if (
                    JWSAlgorithm.Family.RSA.contains(jwsHeader.getAlgorithm()) || JWSAlgorithm.Family.EC.contains(jwsHeader.getAlgorithm())
                ) {
                    // RSA or EC key matcher
                    return new JWKMatcher.Builder()
                        .keyType(KeyType.forAlgorithm(jwsHeader.getAlgorithm()))
                        .keyUses(KeyUse.SIGNATURE, null)
                        .algorithms(jwsHeader.getAlgorithm(), null)
                        .x509CertSHA256Thumbprint(jwsHeader.getX509CertSHA256Thumbprint())
                        .build();
                } else {
                    return null; // Unsupported algorithm
                }
            }

            @Override
            public List<Key> selectJWSKeys(final JWSHeader jwsHeader, final C context) throws KeySourceException {
                JWKMatcher jwkMatcher = createJWKMatcher(jwsHeader);
                if (jwkMatcher == null) {
                    return Collections.emptyList();
                }

                List<JWK> jwkMatches = getJWKSource().get(new JWKSelector(jwkMatcher), context);

                List<Key> sanitizedKeyList = new LinkedList<>();

                for (Key key : KeyConverter.toJavaKeys(jwkMatches)) {
                    if (key instanceof PublicKey || key instanceof SecretKey) {
                        sanitizedKeyList.add(key);
                    } // skip asymmetric private keys
                }

                return sanitizedKeyList;
            }
        };
    }
}
