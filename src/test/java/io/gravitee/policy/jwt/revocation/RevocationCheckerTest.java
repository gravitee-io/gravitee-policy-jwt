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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.policy.jwt.configuration.RevocationCheckConfiguration;
import java.text.ParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCheckerTest {

    @Mock
    private RevocationCheckConfiguration configuration;

    @Mock
    private RevocationCache revocationCache;

    @Mock
    private JWTClaimsSet jwtClaimsSet;

    private RevocationChecker revocationChecker;

    @BeforeEach
    void setUp() {
        revocationChecker = new RevocationChecker(configuration, revocationCache);
    }

    @Test
    void should_return_false_when_revocation_cache_is_null() {
        revocationChecker = new RevocationChecker(configuration, null);

        boolean result = revocationChecker.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void should_return_false_when_claim_not_found_in_token() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenReturn(null);

        boolean result = revocationChecker.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void should_check_revocation_based_on_cache_result(boolean cacheResult) throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenReturn("token123");
        when(revocationCache.contains("token123")).thenReturn(cacheResult);

        boolean result = revocationChecker.isRevoked(jwtClaimsSet);

        assertThat(result).isEqualTo(cacheResult);
    }

    @Test
    void should_return_false_when_parse_exception_occurs() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenThrow(new ParseException("Error parsing claim", 0));

        boolean result = revocationChecker.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }
}
