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
package io.gravitee.policy.jwt.revocation;

import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import java.text.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RevocationCheck {

    private static final Logger log = LoggerFactory.getLogger(RevocationCheck.class);

    private final JWTPolicyConfiguration.RevocationCheck configuration;
    private final RevocationCache revocationCache;

    public RevocationCheck(JWTPolicyConfiguration.RevocationCheck configuration, RevocationCache revocationCache) {
        this.configuration = configuration;
        this.revocationCache = revocationCache;
    }

    public boolean isRevoked(JWTClaimsSet jwtClaimsSet) {
        try {
            if (revocationCache == null) {
                return false;
            }

            String revocationClaim = configuration.getRevocationClaim();
            if (revocationClaim == null || revocationClaim.isEmpty()) {
                log.warn("No revocation claim defined in policy configuration, skipping revocation check");
                return false;
            }

            String claimValue = jwtClaimsSet.getStringClaim(configuration.getRevocationClaim());
            if (claimValue == null) {
                log.warn("Claim {} not found in token, skipping revocation check", revocationClaim);
                return false;
            }

            return revocationCache.getRevokedValues().contains(claimValue);
        } catch (ParseException e) {
            log.warn("Error while parsing revocation claim, skipping revocation check", e);
            return false;
        }
    }
}
