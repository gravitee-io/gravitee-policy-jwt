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
package io.gravitee.policy.jwt.utils;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import lombok.experimental.UtilityClass;

@UtilityClass
public class TokenTypeVerifierFactory {

    public JOSEObjectTypeVerifier<SecurityContext> buildCustom(JWTPolicyConfiguration.TokenTypValidation tokenTypValidation) {
        return (header, context) -> {
            String typ = header.getType() != null ? header.getType() : null;
            if (typ == null) {
                if (tokenTypValidation.isIgnoreMissing()) {
                    return;
                } else {
                    throw new BadJOSEException("Missing typ header");
                }
            }
            tokenTypValidation
                .getExpectedValues()
                .stream()
                .filter(expected -> tokenTypValidation.isIgnoreCase() ? expected.equalsIgnoreCase(typ) : expected.equals(typ))
                .findAny()
                .orElseThrow(() -> new BadJOSEException("Unexpected typ header"));
        };
    }

    public DefaultJOSEObjectTypeVerifier<SecurityContext> buildDefault() {
        return new DefaultJOSEObjectTypeVerifier<>(
            JOSEObjectType.JWT,
            new JOSEObjectType("at+jwt"),
            new JOSEObjectType("application/at+jwt"),
            null
        );
    }

    public JOSEObjectTypeVerifier<SecurityContext> build(JWTPolicyConfiguration.TokenTypValidation tokenTypValidation) {
        if (tokenTypValidation == null || !tokenTypValidation.isEnabled()) {
            return buildDefault();
        } else {
            return buildCustom(tokenTypValidation);
        }
    }
}
