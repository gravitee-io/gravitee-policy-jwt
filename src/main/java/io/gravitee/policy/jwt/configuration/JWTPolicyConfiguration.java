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
package io.gravitee.policy.jwt.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.v3.jwt.resolver.KeyResolver;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Alexandre FARIA (alexandre82.faria at gmail.com)
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JWTPolicyConfiguration implements PolicyConfiguration {

    //settings attributes
    private String resolverParameter;
    private KeyResolver publicKeyResolver = KeyResolver.GIVEN_KEY;
    private Signature signature;
    private boolean extractClaims = false;
    private boolean propagateAuthHeader = true;
    private String userClaim;
    private String clientIdClaim;
    private boolean useSystemProxy;
    private Integer connectTimeout = 2000;
    private Long requestTimeout = 2000L;
    private Boolean followRedirects = false;
    private ConfirmationMethodValidation confirmationMethodValidation = new ConfirmationMethodValidation();
    private TokenTypValidation tokenTypValidation = new TokenTypValidation();
    private RevocationCheck revocationCheck = new RevocationCheck();

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    public static class ConfirmationMethodValidation {

        private boolean ignoreMissing = false;
        private CertificateBoundThumbprint certificateBoundThumbprint = new CertificateBoundThumbprint();
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    public static class CertificateBoundThumbprint {

        private boolean enabled = false;
        private boolean extractCertificateFromHeader = false;
        private String headerName = "ssl-client-cert";
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    public static class TokenTypValidation {

        private boolean enabled = false;
        private boolean ignoreMissing = false;
        private List<String> expectedValues = List.of("JWT");
        private boolean ignoreCase = false;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    @Builder(toBuilder = true)
    public static class RevocationCheck {

        private static final Logger log = LoggerFactory.getLogger(RevocationCheck.class);

        public static final Integer DEFAULT_REFRESH_INTERVAL = 300;
        public static final Integer DEFAULT_CONNECT_TIMEOUT = 2000;
        public static final Long DEFAULT_REQUEST_TIMEOUT = 2000L;
        public static final String DEFAULT_REVOCATION_CLAIM = "jti";

        private boolean enabled = false;
        private String revocationClaim = DEFAULT_REVOCATION_CLAIM;
        private String revocationListUrl;
        private Integer refreshInterval = DEFAULT_REFRESH_INTERVAL;
        private Integer connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Long requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private boolean followRedirects = false;
        private boolean useSystemProxy = false;
        private AuthConfiguration auth = new AuthConfiguration();

        public boolean isValid() {
            if (revocationListUrl == null || revocationListUrl.isEmpty()) {
                log.error("Revocation list url is not defined in policy configuration so revocation check will not be initialized");
                return false;
            }

            try {
                new URL(revocationListUrl);
            } catch (MalformedURLException e) {
                log.error("Invalid revocation list URL format so revocation check will not be initialized: {}", revocationListUrl);
                return false;
            }

            return true;
        }

        public RevocationCheck normalized() {
            RevocationCheck.RevocationCheckBuilder builder = this.toBuilder();

            if (this.refreshInterval == null || this.refreshInterval <= 0) {
                log.warn(
                    "Revocation list refresh interval is not defined or is not a positive number. " + "Using default value of {} seconds.",
                    DEFAULT_REFRESH_INTERVAL
                );
                builder.refreshInterval(DEFAULT_REFRESH_INTERVAL);
            }

            if (this.revocationClaim == null || this.revocationClaim.isEmpty()) {
                log.warn("Revocation claim is not defined in policy configuration. Using default value of {}.", DEFAULT_REVOCATION_CLAIM);
                builder.revocationClaim(DEFAULT_REVOCATION_CLAIM);
            }

            if (this.connectTimeout == null || this.connectTimeout <= 0) {
                log.warn("Revocation list connect timeout is not defined or is not a positive number. Using default value of {} ms.", 2000);
                builder.connectTimeout(DEFAULT_CONNECT_TIMEOUT);
            }

            if (this.requestTimeout == null || this.requestTimeout <= 0) {
                log.warn(
                    "Revocation list request timeout is not defined or is not a positive number. Using default value of {} ms.",
                    2000L
                );
                builder.requestTimeout(DEFAULT_REQUEST_TIMEOUT);
            }

            return builder.build();
        }
    }
}
