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
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import java.text.ParseException;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCheckTest {

    @Mock
    private JWTPolicyConfiguration.RevocationCheck configuration;

    @Mock
    private RevocationCache revocationCache;

    @Mock
    private JWTClaimsSet jwtClaimsSet;

    private RevocationCheck revocationCheck;

    @BeforeEach
    void setUp() {
        revocationCheck = new RevocationCheck(configuration, revocationCache);
    }

    @Test
    void shouldReturnFalseWhenRevocationCacheIsNull() {
        revocationCheck = new RevocationCheck(configuration, null);

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void shouldReturnFalseWhenRevocationClaimIsNull() {
        when(configuration.getRevocationClaim()).thenReturn(null);

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void shouldReturnFalseWhenRevocationClaimIsEmpty() {
        when(configuration.getRevocationClaim()).thenReturn("");

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void shouldReturnFalseWhenClaimNotFoundInToken() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenReturn(null);

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void shouldReturnFalseWhenClaimValueNotInRevocationList() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenReturn("token123");
        when(revocationCache.getRevokedValues()).thenReturn(Set.of("otherToken"));

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }

    @Test
    void shouldReturnTrueWhenClaimValueIsInRevocationList() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenReturn("token123");
        when(revocationCache.getRevokedValues()).thenReturn(Set.of("token123"));

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isTrue();
    }

    @Test
    void shouldReturnFalseWhenParseExceptionOccurs() throws ParseException {
        when(configuration.getRevocationClaim()).thenReturn("jti");
        when(jwtClaimsSet.getStringClaim("jti")).thenThrow(new ParseException("Error parsing claim", 0));

        boolean result = revocationCheck.isRevoked(jwtClaimsSet);

        assertThat(result).isFalse();
    }
}
