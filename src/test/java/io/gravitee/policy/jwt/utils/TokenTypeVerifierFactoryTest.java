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

import static org.assertj.core.api.Assertions.*;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import java.util.List;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class TokenTypeVerifierFactoryTest {

    @Test
    void buildDefault_should_return_default_verifier() {
        DefaultJOSEObjectTypeVerifier<SecurityContext> verifier = TokenTypeVerifierFactory.buildDefault();
        assertThat(verifier).isNotNull();
        assertThat(verifier.getAllowedTypes()).containsExactlyInAnyOrder(
            JOSEObjectType.JWT,
            new JOSEObjectType("at+jwt"),
            new JOSEObjectType("application/at+jwt"),
            null
        );
    }

    @Test
    void build_should_return_default_verifier_when_tokenTypValidation_is_null() {
        JOSEObjectTypeVerifier<SecurityContext> verifier = TokenTypeVerifierFactory.build(null);
        assertThat(verifier).isInstanceOf(DefaultJOSEObjectTypeVerifier.class);
    }

    @Test
    void build_should_return_default_verifier_when_tokenTypValidation_is_disabled() {
        JWTPolicyConfiguration.TokenTypValidation tokenTypValidation = new JWTPolicyConfiguration.TokenTypValidation();
        tokenTypValidation.setEnabled(false);
        JOSEObjectTypeVerifier<SecurityContext> verifier = TokenTypeVerifierFactory.build(tokenTypValidation);
        assertThat(verifier).isInstanceOf(DefaultJOSEObjectTypeVerifier.class);
    }

    @Test
    void build_should_return_custom_verifier_when_tokenTypValidation_is_enabled() {
        JWTPolicyConfiguration.TokenTypValidation tokenTypValidation = new JWTPolicyConfiguration.TokenTypValidation();
        tokenTypValidation.setEnabled(true);
        tokenTypValidation.setIgnoreCase(true);
        tokenTypValidation.setIgnoreMissing(false);
        tokenTypValidation.setExpectedValues(List.of("JWT", "at+jwt"));

        JOSEObjectTypeVerifier<SecurityContext> verifier = TokenTypeVerifierFactory.build(tokenTypValidation);
        assertThat(verifier).isNotInstanceOf(DefaultJOSEObjectTypeVerifier.class).isInstanceOf(JOSEObjectTypeVerifier.class);
    }
}
