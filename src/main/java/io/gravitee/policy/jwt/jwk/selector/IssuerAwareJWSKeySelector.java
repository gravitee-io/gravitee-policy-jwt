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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Specific implementation of {@link JWSKeySelector} that holds a map of multiple {@link JWSKeySelector}s indexed by issuer.
 * It is able to select the key candidates for verifying a signed JWT depending on the issuer.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class IssuerAwareJWSKeySelector implements JWTClaimsSetAwareJWSKeySelector<SecurityContext> {

    private final String defaultIssuer;
    private final Map<String, JWSKeySelector<SecurityContext>> selectors;

    public IssuerAwareJWSKeySelector(String defaultIssuer, Map<String, JWSKeySelector<SecurityContext>> selectors) {
        this.defaultIssuer = defaultIssuer;
        this.selectors = selectors;
    }

    /**
     * {@inheritDoc}
     *
     * Basically, selects the {@link JWSKeySelector} corresponding to the issuer and delegates the call to it.
     * If no {@link JWSKeySelector} corresponds to the JWT issuer, fallback to the given default {@link JWSKeySelector}.
     * If not {@link JWSKeySelector} is found, returns an empty list of keys.
     */
    @Override
    public List<? extends Key> selectKeys(JWSHeader jwsHeader, JWTClaimsSet jwtClaimsSet, SecurityContext securityContext)
        throws KeySourceException {
        final String claimsSetIssuer = jwtClaimsSet.getIssuer();
        final String issuer = claimsSetIssuer != null ? claimsSetIssuer : defaultIssuer;

        if (issuer == null) {
            return Collections.emptyList();
        }

        final JWSKeySelector<SecurityContext> selector = this.selectors.get(issuer);

        if (selector != null) {
            return selector.selectJWSKeys(jwsHeader, securityContext);
        }

        return Collections.emptyList();
    }
}
