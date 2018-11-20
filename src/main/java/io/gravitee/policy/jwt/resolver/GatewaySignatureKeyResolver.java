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
package io.gravitee.policy.jwt.resolver;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.text.ParseException;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GatewaySignatureKeyResolver implements SignatureKeyResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(GatewaySignatureKeyResolver.class);

    private static final String DEFAULT_KID = "default";
    private static final String KEY_PROPERTY = "policy.jwt.issuer.%s.%s";

    private final Environment environment;
    private final String token;

    public GatewaySignatureKeyResolver(Environment environment, String token) {
        this.environment = environment;
        this.token = token;
    }

    @Override
    public String resolve() {
        try {
            final JWT jwt = JWTParser.parse(token);

            final String iss = jwt.getJWTClaimsSet().getIssuer();
            String keyId = ((JWSHeader)jwt.getHeader()).getKeyID();

            if (keyId == null || keyId.isEmpty()) {
                keyId = DEFAULT_KID;
            }

            String publicKey = environment.getProperty(String.format(KEY_PROPERTY, iss, keyId));
            return (publicKey == null || publicKey.trim().isEmpty()) ? null : publicKey;
        } catch (ParseException pe) {
            LOGGER.debug("Unexpected error while parsing JWT", pe);
        }

        return null;
    }
}
