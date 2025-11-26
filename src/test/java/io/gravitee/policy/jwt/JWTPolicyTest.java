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
package io.gravitee.policy.jwt;

import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_JWT;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_JWT_CLAIMS;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID;
import static io.gravitee.policy.jwt.JWTPolicy.CONTEXT_ATTRIBUTE_TOKEN;
import static io.gravitee.policy.jwt.JWTPolicy.JWT_INVALID_TOKEN_KEY;
import static io.gravitee.policy.jwt.JWTPolicy.JWT_MISSING_TOKEN_KEY;
import static io.gravitee.policy.jwt.JWTPolicy.JWT_REVOKED;
import static io.gravitee.policy.jwt.JWTPolicy.UNAUTHORIZED_MESSAGE;
import static io.gravitee.reporter.api.http.SecurityType.JWT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.configuration.RevocationCheckConfiguration;
import io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider;
import io.gravitee.policy.jwt.revocation.RevocationChecker;
import io.gravitee.reporter.api.v4.metric.Metrics;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.observers.TestObserver;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class JWTPolicyTest {

    private static final String TOKEN =
        "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJ1bml0LXRlc3QiLCJhdWQiOiJ1bml0LXRlc3QiLCJpc3MiOiJodHRwczovL2dyYXZpdGVlLmlvIiwiZXhwIjoyMDU0MjU5MTMzLCJpYXQiOjE2NTQyNDQ3MzN9.Id0kPGSeJ9YKLJzR1Rm2V22MpRyQTnVUEXedyN8N0tk";
    private static final String TOKEN_WITHOUT_CLIENT_ID =
        "eyJraWQiOiJkZWZhdWx0IiwidHlwIjoiSldUIiwiYWxnIjoiSFMyNTYifQ.eyJpc3MiOiJodHRwczovL2dyYXZpdGVlLmlvIiwiZXhwIjoyMDU0MjU5MTMzLCJpYXQiOjE2NTQyNDQ3MzN9.N0RbUB1UYLWOz2aRacZ-nP6mPAi7UJrM13COMmHczgs";
    private static final String STANDARD_SUBJECT = "StandardSubject";
    private static final String AZP_CLIENT_ID = "azpClientId";
    private static final String CUSTOM_CLAIM_CLIENT_ID = "ClientIdClaim";
    private static final String CUSTOM_CLAIM_CLIENT_ID_VALUE = "CustomClaimClientIdValue";
    private static final String AUDIENCE_CLIENT_ID = "AudienceClientId";
    private static final String CLIENT_ID = "clientId";
    private static final String ISSUER = "https://gravitee.io";
    private static final String MOCK_EXCEPTION = "Mock exception";
    private static final String MOCK_JOSE_EXCEPTION = "Mock JOSE exception";
    private static final String CUSTOM_CLAIM_USER = "UserClaim";
    private static final String CUSTOM_CLAIM_USER_VALUE = "CustomClaimUser";

    @Mock
    private JWTPolicyConfiguration configuration;

    @Mock
    private DefaultJWTProcessorProvider jwtProcessorResolver;

    @Mock
    private JWTProcessor<SecurityContext> jwtProcessor;

    @Mock
    private HttpPlainExecutionContext ctx;

    @Mock
    private HttpPlainRequest request;

    @Mock
    private RevocationChecker revocationChecker;

    private JWTPolicy cut;

    @BeforeEach
    void init() {
        cut = new JWTPolicy(configuration);
        prepareClaimsSetCacheMocking();
        ReflectionTestUtils.setField(cut, "jwtProcessorResolver", jwtProcessorResolver);
        ReflectionTestUtils.setField(cut, "revocationChecker", revocationChecker);
    }

    private void prepareClaimsSetCacheMocking() {
        lenient().when(ctx.getAttribute(ATTR_API)).thenReturn("API_ID");
        lenient().when(ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT)).thenReturn(null);
    }

    private static Stream<Arguments> provideClientIdParameters() {
        return Stream.of(
            Arguments.of(CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, AZP_CLIENT_ID, STANDARD_SUBJECT),
            Arguments.of(CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, AZP_CLIENT_ID, CUSTOM_CLAIM_USER_VALUE),
            Arguments.of(CUSTOM_CLAIM_CLIENT_ID, CUSTOM_CLAIM_CLIENT_ID_VALUE, STANDARD_SUBJECT),
            Arguments.of(JWTClaimNames.AUDIENCE, AUDIENCE_CLIENT_ID, STANDARD_SUBJECT),
            Arguments.of(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID, STANDARD_SUBJECT)
        );
    }

    @ParameterizedTest
    @MethodSource("provideClientIdParameters")
    void should_verify_token_with_client_id(String clientIdField, String expectedClientId, String expectedSubject)
        throws BadJOSEException, JOSEException {
        final Metrics metrics = mock(Metrics.class);
        final HttpHeaders headers = mock(HttpHeaders.class);
        final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .claim(clientIdField, expectedClientId)
            .expirationTime(new Date(System.currentTimeMillis() + 3600000));

        if (STANDARD_SUBJECT.equals(expectedSubject)) {
            claimsSetBuilder.subject(expectedSubject);
        } else {
            when(configuration.getUserClaim()).thenReturn(CUSTOM_CLAIM_USER);
            claimsSetBuilder.claim(CUSTOM_CLAIM_USER, expectedSubject);
        }

        if (CUSTOM_CLAIM_CLIENT_ID_VALUE.equals(expectedClientId)) {
            when(configuration.getClientIdClaim()).thenReturn(CUSTOM_CLAIM_CLIENT_ID);
        }

        final JWTClaimsSet claimsSet = claimsSetBuilder.build();

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID)).thenReturn(expectedClientId);
        when(ctx.getAttribute(ATTR_USER)).thenReturn(expectedSubject);
        when(request.headers()).thenReturn(headers);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();

        obs.assertComplete();

        verifyMetricsAttributesAndHeaders(metrics, headers, expectedClientId, expectedSubject);
    }

    @Test
    void should_verify_token_from_request() throws BadJOSEException, JOSEException {
        final Metrics metrics = mock(Metrics.class);
        final HttpHeaders headers = mock(HttpHeaders.class);
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject(STANDARD_SUBJECT)
            .claim(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID)
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID)).thenReturn(CLIENT_ID);
        when(ctx.getAttribute(ATTR_USER)).thenReturn(STANDARD_SUBJECT);
        when(request.headers()).thenReturn(headers);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verifyMetricsAttributesAndHeaders(metrics, headers, CLIENT_ID, STANDARD_SUBJECT);
    }

    @Test
    void should_verify_token_from_context() throws BadJOSEException, JOSEException, ParseException {
        final Metrics metrics = mock(Metrics.class);
        final HttpHeaders headers = mock(HttpHeaders.class);

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject(STANDARD_SUBJECT)
            .claim(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID)
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID)).thenReturn(CLIENT_ID);
        when(ctx.getAttribute(ATTR_USER)).thenReturn(STANDARD_SUBJECT);
        when(request.headers()).thenReturn(headers);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT)).thenReturn(new LazyJWT(TOKEN));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        // Verify context attributes.
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_TOKEN, TOKEN);
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, CLIENT_ID);
        verify(ctx).setAttribute(ATTR_USER, STANDARD_SUBJECT);

        // Verify request headers.
        verify(headers).remove(io.vertx.rxjava3.core.http.HttpHeaders.AUTHORIZATION);
    }

    @Test
    void should_verify_token_and_extract_claims_when_extract_claims_is_configured() throws BadJOSEException, JOSEException {
        final Metrics metrics = mock(Metrics.class);
        final HttpHeaders headers = mock(HttpHeaders.class);
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject(STANDARD_SUBJECT)
            .claim(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID)
            .jwtID("jwtId")
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(request.headers()).thenReturn(headers);
        when(configuration.isExtractClaims()).thenReturn(true);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID)).thenReturn(CLIENT_ID);
        when(ctx.getAttribute(ATTR_USER)).thenReturn(STANDARD_SUBJECT);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verifyMetricsAttributesAndHeaders(metrics, headers, CLIENT_ID, STANDARD_SUBJECT);
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claimsSet.getClaims());
    }

    @Test
    void should_verify_token_and_check_revocation_when_revocation_check_is_configured() throws BadJOSEException, JOSEException {
        final Metrics metrics = mock(Metrics.class);
        final HttpHeaders headers = mock(HttpHeaders.class);
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject(STANDARD_SUBJECT)
            .claim(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID)
            .jwtID("testJti") // Adding jwtID for revocation check
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(request.headers()).thenReturn(headers);
        when(configuration.isExtractClaims()).thenReturn(true);
        when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID)).thenReturn(CLIENT_ID);
        when(ctx.getAttribute(ATTR_USER)).thenReturn(STANDARD_SUBJECT);

        // Configure revocation check
        RevocationCheckConfiguration revocationCheckConfiguration = mock(RevocationCheckConfiguration.class);
        when(configuration.getRevocationCheck()).thenReturn(revocationCheckConfiguration);
        when(revocationCheckConfiguration.isEnabled()).thenReturn(true);
        when(revocationChecker.isRevoked(claimsSet)).thenReturn(false);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(revocationChecker).isRevoked(claimsSet);
        verifyMetricsAttributesAndHeaders(metrics, headers, CLIENT_ID, STANDARD_SUBJECT);
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claimsSet.getClaims());
    }

    @Test
    void should_error_with_401_if_revocation_claim_is_revoked_and_revocation_check_is_configured() throws BadJOSEException, JOSEException {
        final HttpHeaders headers = mock(HttpHeaders.class);
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .subject(STANDARD_SUBJECT)
            .claim(CONTEXT_ATTRIBUTE_CLIENT_ID, CLIENT_ID)
            .jwtID("revokedJti") // Adding revoked jwtID
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(any(JWT.class), isNull())).thenReturn(claimsSet);
        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);

        // Configure revocation check to fail
        RevocationCheckConfiguration revocationCheckConfiguration = mock(RevocationCheckConfiguration.class);
        when(configuration.getRevocationCheck()).thenReturn(revocationCheckConfiguration);
        when(revocationCheckConfiguration.isEnabled()).thenReturn(true);
        when(revocationChecker.isRevoked(claimsSet)).thenReturn(true);
        when(ctx.interruptWith(any())).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(revocationChecker).isRevoked(claimsSet);
        verify(ctx).interruptWith(
            argThat(failure -> {
                assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                assertEquals(UNAUTHORIZED_MESSAGE, failure.message());
                assertEquals(JWT_REVOKED, failure.key());
                assertNull(failure.parameters());
                assertNull(failure.contentType());
                return true;
            })
        );
    }

    @Test
    void should_error_with_401_missing_token_interruption_when_no_authorization_header() {
        final HttpHeaders headers = mock(HttpHeaders.class);
        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.interruptWith(any())).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx).interruptWith(
            argThat(failure -> {
                assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                assertEquals(UNAUTHORIZED_MESSAGE, failure.message());
                assertEquals(JWT_MISSING_TOKEN_KEY, failure.key());
                assertNull(failure.parameters());
                assertNull(failure.contentType());

                return true;
            })
        );
    }

    @Test
    void should_error_with_401_missing_token_interruption_when_no_token() {
        final HttpHeaders headers = mock(HttpHeaders.class);

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(Collections.emptyList());
        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.interruptWith(any())).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx).interruptWith(
            argThat(failure -> {
                assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                assertEquals(UNAUTHORIZED_MESSAGE, failure.message());
                assertEquals(JWT_MISSING_TOKEN_KEY, failure.key());
                assertNull(failure.parameters());
                assertNull(failure.contentType());

                return true;
            })
        );
    }

    @Test
    void should_error_with_401_invalid_token_interruption_when_token_empty() {
        final HttpHeaders headers = mock(HttpHeaders.class);

        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer "));
        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(ctx.interruptWith(any())).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx).interruptWith(
            argThat(failure -> {
                assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                assertEquals(UNAUTHORIZED_MESSAGE, failure.message());
                assertEquals(JWT_INVALID_TOKEN_KEY, failure.key());
                assertNull(failure.parameters());
                assertNull(failure.contentType());

                return true;
            })
        );
    }

    @Test
    void should_error_with_401_invalid_token_interruption_when_token_rejected() throws BadJOSEException, JOSEException {
        final Metrics metrics = mock(Metrics.class);

        final HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));
        when(request.headers()).thenReturn(headers);

        when(jwtProcessorResolver.provide(ctx)).thenReturn(Maybe.just(jwtProcessor));
        when(jwtProcessor.process(Mockito.<JWT>argThat(jwt -> TOKEN.equals(jwt.getParsedString())), isNull())).thenThrow(
            new JOSEException(MOCK_JOSE_EXCEPTION)
        );
        when(ctx.request()).thenReturn(request);
        when(ctx.metrics()).thenReturn(metrics);
        when(ctx.interruptWith(any())).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx).interruptWith(
            argThat(failure -> {
                assertEquals(HttpStatusCode.UNAUTHORIZED_401, failure.statusCode());
                assertEquals(UNAUTHORIZED_MESSAGE, failure.message());
                assertEquals(JWT_INVALID_TOKEN_KEY, failure.key());
                assertNull(failure.parameters());
                assertNull(failure.contentType());

                return true;
            })
        );

        verify(metrics).setErrorMessage(MOCK_JOSE_EXCEPTION);
    }

    @Test
    void should_return_order_0() {
        assertEquals(0, cut.order());
    }

    @Test
    void should_return_jwt_policy_id() {
        assertEquals("jwt", cut.id());
    }

    @Test
    void should_validate_subscription() {
        assertTrue(cut.requireSubscription());
    }

    @Test
    void extractSecurityToken_should_return_securityToken_when_token_is_present() {
        final HttpHeaders headers = mock(HttpHeaders.class);

        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN));

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertValue(
            token -> token.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) && token.getTokenValue().equals("unit-test")
        );
        verify(ctx).setAttribute(eq(CONTEXT_ATTRIBUTE_JWT), Mockito.<LazyJWT>argThat(jwt -> TOKEN.equals(jwt.getToken())));
    }

    @Test
    void extractSecurityToken_should_return_invalid_securityToken_when_token_contains_no_clientId() {
        final HttpHeaders headers = mock(HttpHeaders.class);

        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);
        when(headers.getAll(HttpHeaderNames.AUTHORIZATION)).thenReturn(List.of("Bearer " + TOKEN_WITHOUT_CLIENT_ID));

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs
            .assertComplete()
            .assertValueCount(1)
            .assertValue(securityToken -> {
                assertThat(securityToken.getTokenType()).isEqualTo(SecurityToken.TokenType.CLIENT_ID.name());
                assertThat(securityToken.isInvalid()).isTrue();
                return true;
            });
    }

    @Test
    void extractSecurityToken_should_return_empty_when_token_is_absent() {
        final HttpHeaders headers = mock(HttpHeaders.class);

        when(ctx.request()).thenReturn(request);
        when(request.headers()).thenReturn(headers);

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertComplete().assertValueCount(0);
    }

    private void verifyMetricsAttributesAndHeaders(Metrics metrics, HttpHeaders headers, String expectedClientId, String expectedSubject) {
        // Verify context attributes.
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_TOKEN, TOKEN);
        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, expectedClientId);
        verify(ctx).setAttribute(ATTR_USER, expectedSubject);

        // Verify metrics.
        verify(metrics).setUser(expectedSubject);
        verify(metrics).setSecurityType(JWT);
        verify(metrics).setSecurityToken(expectedClientId);

        // Verify request headers.
        verify(headers).remove(io.vertx.rxjava3.core.http.HttpHeaders.AUTHORIZATION);
    }
}
