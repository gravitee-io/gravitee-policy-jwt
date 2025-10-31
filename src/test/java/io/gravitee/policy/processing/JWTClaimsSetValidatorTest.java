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
package io.gravitee.policy.processing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.reactive.api.context.ContextAttributes;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.policy.helpers.JWTTokenGenerator;
import java.text.ParseException;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class JWTClaimsSetValidatorTest {

    private static SignedJWT FAKE_SIGNED_JWT = JWTTokenGenerator.createValidSignedToken(3600 * 1000L);
    private static String FAKE_SIGNED_JWT_STRING_TOKEN = FAKE_SIGNED_JWT.serialize();

    @Mock
    private BaseExecutionContext ctx;

    @Mock
    private JWTProcessor<SecurityContext> jwtProcessor;

    @BeforeEach
    void setUp() {
        when(ctx.getAttribute(ContextAttributes.ATTR_API)).thenReturn("API_ID");
    }

    @Test
    void should_create_JWT_claims_set_validator() {
        JWTClaimsSetValidator jwtClaimsSetValidator = JWTClaimsSetValidator.create(ctx);
        assertThat(jwtClaimsSetValidator).isNotNull();
        assertThat(jwtClaimsSetValidator.validClaimsSetCache.getName()).startsWith("JWT_API_ID");
    }

    @Test
    void should_extract_and_cache_jwt_claims_set() throws BadJOSEException, JOSEException, ParseException {
        JWTClaimsSetValidator validator = JWTClaimsSetValidator.create(ctx);
        JWTClaimsSet expectedClaimSet = mockJwtClaimsSetProcessing(FAKE_SIGNED_JWT_STRING_TOKEN);

        JWTClaimsSet result = validator.extract(jwtProcessor, new LazyJWT(FAKE_SIGNED_JWT_STRING_TOKEN));

        assertThat(result).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(FAKE_SIGNED_JWT_STRING_TOKEN, expectedClaimSet));
    }

    @Test
    void should_reuse_claims_set_from_cache() throws BadJOSEException, JOSEException, ParseException {
        // Given a first call to cache the Claims set
        JWTClaimsSetValidator validator = JWTClaimsSetValidator.create(ctx);
        JWTClaimsSet expectedClaimSet = mockJwtClaimsSetProcessing(FAKE_SIGNED_JWT_STRING_TOKEN);

        JWTClaimsSet firstClaimsSet = validator.extract(jwtProcessor, new LazyJWT(FAKE_SIGNED_JWT_STRING_TOKEN));

        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(FAKE_SIGNED_JWT_STRING_TOKEN, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());

        // When doing a second call
        JWTClaimsSet result = validator.extract(jwtProcessor, new LazyJWT(FAKE_SIGNED_JWT_STRING_TOKEN));

        // Then processing should not have been called again
        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(FAKE_SIGNED_JWT_STRING_TOKEN, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());
    }

    @Test
    void should_reuse_claims_set_from_cache_when_expired_less_than_60_seconds() throws BadJOSEException, JOSEException, ParseException {
        // Given a first call to cache the Claims set
        JWTClaimsSetValidator validator = JWTClaimsSetValidator.create(ctx);
        // Generate a valid token that expires during the expiration tolerance period (60 seconds). Here we use 30 seconds in the past
        String immediatlyExpiredToken = JWTTokenGenerator.createValidSignedToken(-30 * 1000L).serialize();
        JWTClaimsSet expectedClaimSet = mockJwtClaimsSetProcessing(immediatlyExpiredToken);

        JWTClaimsSet firstClaimsSet = validator.extract(jwtProcessor, new LazyJWT(immediatlyExpiredToken));

        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(immediatlyExpiredToken, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());

        // When doing a second call
        JWTClaimsSet result = validator.extract(jwtProcessor, new LazyJWT(immediatlyExpiredToken));

        // Then processing should have been called again
        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(immediatlyExpiredToken, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());
    }

    @Test
    void should_not_reuse_claims_set_from_cache_when_expired() throws BadJOSEException, JOSEException, ParseException {
        // Given a first call to cache the Claims set
        JWTClaimsSetValidator validator = JWTClaimsSetValidator.create(ctx);
        // Generate a valid token that expires in the past to avoid the clock skew tolerance of 60 seconds. Here we use 100 seconds in the past
        String immediatlyExpiredToken = JWTTokenGenerator.createValidSignedToken(-100 * 1000L).serialize();
        JWTClaimsSet expectedClaimSet = mockJwtClaimsSetProcessing(immediatlyExpiredToken);

        JWTClaimsSet firstClaimsSet = validator.extract(jwtProcessor, new LazyJWT(immediatlyExpiredToken));

        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(immediatlyExpiredToken, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());

        // When doing a second call
        JWTClaimsSet result = validator.extract(jwtProcessor, new LazyJWT(immediatlyExpiredToken));

        // Then processing should have been called again
        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(immediatlyExpiredToken, expectedClaimSet));
        verify(jwtProcessor, times(2)).process(any(JWT.class), any());
    }

    @Test
    void should_invalidate_jwt() throws BadJOSEException, ParseException, JOSEException {
        // Given
        JWTClaimsSetValidator validator = JWTClaimsSetValidator.create(ctx);
        JWTClaimsSet expectedClaimSet = mockJwtClaimsSetProcessing(FAKE_SIGNED_JWT_STRING_TOKEN);

        JWTClaimsSet firstClaimsSet = validator.extract(jwtProcessor, new LazyJWT(FAKE_SIGNED_JWT_STRING_TOKEN));

        assertThat(firstClaimsSet).isEqualTo(expectedClaimSet);
        assertThat(validator.validClaimsSetCache.entrySet())
            .hasSize(1)
            .containsExactly(Map.entry(FAKE_SIGNED_JWT_STRING_TOKEN, expectedClaimSet));
        verify(jwtProcessor, times(1)).process(any(JWT.class), any());

        // When doing a second call
        JWTClaimsSet result = validator.invalidate(new LazyJWT(FAKE_SIGNED_JWT_STRING_TOKEN));

        // Then
        assertThat(result).isSameAs(firstClaimsSet);
        assertThat(validator.validClaimsSetCache.entrySet()).isEmpty();
    }

    private JWTClaimsSet mockJwtClaimsSetProcessing(String token) throws ParseException, BadJOSEException, JOSEException {
        JWTClaimsSet expectedClaimSet = new LazyJWT(token).getDelegate().getJWTClaimsSet();
        when(jwtProcessor.process(any(JWT.class), any())).thenReturn(expectedClaimSet);
        return expectedClaimSet;
    }
}
