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
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

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
    private RevocationCheckConfiguration revocationCheck = new RevocationCheckConfiguration();

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
}
