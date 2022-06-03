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
package io.gravitee.policy.jwt.jwk.provider;

import static io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider.RESOLVED_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.reactive.api.context.RequestExecutionContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.AbstractJWKTest;
import io.gravitee.policy.v3.jwt.resolver.KeyResolver;
import io.reactivex.Maybe;
import io.reactivex.observers.TestObserver;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unchecked")
@ExtendWith(MockitoExtension.class)
class DefaultJWTProcessorProviderTest extends AbstractJWKTest {

    private static final String KEY = "key", EL_EXPRESSION = "{# request.headers['origin'] == 'https://gravitee.io'";

    @Mock
    private JWTPolicyConfiguration configuration;

    @Mock
    private RequestExecutionContext ctx;

    @Mock
    private TemplateEngine templateEngine;

    public static Stream<Arguments> provideParameters() {
        return Stream.of(
            Arguments.of(KeyResolver.GIVEN_KEY, GivenKeyJWTProcessorProvider.class),
            Arguments.of(KeyResolver.GATEWAY_KEYS, GatewayKeysJWTProcessorProvider.class),
            Arguments.of(KeyResolver.JWKS_URL, JwksUrlJWTProcessorProvider.class)
        );
    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    void shouldProvideDependingOnConfiguredKeyResolver(KeyResolver keyResolver, Class<JWTProcessorProvider> providerClass) {
        final JWTProcessor<SecurityContext> jwtProcessor = mock(JWTProcessor.class);

        when(configuration.getPublicKeyResolver()).thenReturn(keyResolver);
        when(configuration.getResolverParameter()).thenReturn(KEY);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(KEY, String.class)).thenReturn(KEY);

        final DefaultJWTProcessorProvider cut = new DefaultJWTProcessorProvider(configuration);

        final JWTProcessorProvider jwtProcessorProvider = spyJWTProcessorProvider(cut);
        final Map<String, JWTProcessor<SecurityContext>> cachedProcessors = spyJWTProcessors(cut);

        // Check expected provider instance.
        assertTrue(providerClass.isAssignableFrom(jwtProcessorProvider.getClass()));
        doReturn(Maybe.just(jwtProcessor)).when(jwtProcessorProvider).provide(ctx);

        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();
        obs.assertResult(jwtProcessor);

        // Check the evaluated EL has been pushed to internal context for eventually reuse.
        verify(ctx).putInternalAttribute(RESOLVED_PARAMETER, KEY);

        // Check the JWTProcessor has been put in cache.
        assertEquals(jwtProcessor, cachedProcessors.get(KEY));
    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    void shouldHitTheCacheWhenAlreadyProvided(KeyResolver keyResolver) {
        final JWTProcessor<SecurityContext> jwtProcessor = mock(JWTProcessor.class);

        when(configuration.getPublicKeyResolver()).thenReturn(keyResolver);
        when(configuration.getResolverParameter()).thenReturn(KEY);

        final DefaultJWTProcessorProvider cut = new DefaultJWTProcessorProvider(configuration);

        final JWTProcessorProvider jwtProcessorProvider = spyJWTProcessorProvider(cut);
        final Map<String, JWTProcessor<SecurityContext>> cachedProcessors = spyJWTProcessors(cut);

        cachedProcessors.put(KEY, jwtProcessor);

        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();
        obs.assertResult(jwtProcessor);

        verifyNoInteractions(templateEngine);
        verifyNoInteractions(jwtProcessorProvider);
    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    void shouldPutInCacheWithResolvedParameterWhenElExpression(KeyResolver keyResolver, Class<JWTProcessorProvider> providerClass) {
        final JWTProcessor<SecurityContext> jwtProcessor = mock(JWTProcessor.class);

        when(configuration.getPublicKeyResolver()).thenReturn(keyResolver);
        when(configuration.getResolverParameter()).thenReturn(EL_EXPRESSION);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(EL_EXPRESSION, String.class)).thenReturn(KEY);

        final DefaultJWTProcessorProvider cut = new DefaultJWTProcessorProvider(configuration);

        final JWTProcessorProvider jwtProcessorProvider = spyJWTProcessorProvider(cut);
        final Map<String, JWTProcessor<SecurityContext>> cachedProcessors = spyJWTProcessors(cut);

        // Check expected provider instance.
        assertTrue(providerClass.isAssignableFrom(jwtProcessorProvider.getClass()));
        doReturn(Maybe.just(jwtProcessor)).when(jwtProcessorProvider).provide(ctx);

        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();
        obs.assertResult(jwtProcessor);

        // Check the evaluated EL has been pushed to internal context for eventually reuse.
        verify(ctx).putInternalAttribute(RESOLVED_PARAMETER, KEY);

        // Check the JWTProcessor has been put in cache with the resolved EL expression.
        assertEquals(jwtProcessor, cachedProcessors.get(KEY));
    }

    @ParameterizedTest
    @MethodSource("provideParameters")
    void shouldHitTheCacheWithResolvedParameterWhenElExpression(KeyResolver keyResolver, Class<JWTProcessorProvider> providerClass) {
        final JWTProcessor<SecurityContext> jwtProcessor = mock(JWTProcessor.class);

        when(configuration.getPublicKeyResolver()).thenReturn(keyResolver);
        when(configuration.getResolverParameter()).thenReturn(EL_EXPRESSION);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(EL_EXPRESSION, String.class)).thenReturn(KEY);

        final DefaultJWTProcessorProvider cut = new DefaultJWTProcessorProvider(configuration);

        final JWTProcessorProvider jwtProcessorProvider = spyJWTProcessorProvider(cut);
        final Map<String, JWTProcessor<SecurityContext>> cachedProcessors = spyJWTProcessors(cut);

        cachedProcessors.put(KEY, jwtProcessor);

        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();
        obs.assertResult(jwtProcessor);

        // Check cache tried with non resolved expression then resolved.
        verify(cachedProcessors).get(EL_EXPRESSION);
        verify(cachedProcessors).get(KEY);
        verifyNoInteractions(jwtProcessorProvider);
    }

    private JWTProcessorProvider spyJWTProcessorProvider(JWTProcessorProvider cut) {
        final JWTProcessorProvider jwtProcessorProvider = spy(
            (JWTProcessorProvider) Objects.requireNonNull(ReflectionTestUtils.getField(cut, "jwtProcessorProvider"))
        );
        ReflectionTestUtils.setField(cut, "jwtProcessorProvider", jwtProcessorProvider);
        return jwtProcessorProvider;
    }

    private Map<String, JWTProcessor<SecurityContext>> spyJWTProcessors(JWTProcessorProvider cut) {
        final Map<String, JWTProcessor<SecurityContext>> jwtProcessors = spy(
            (Map<String, JWTProcessor<SecurityContext>>) Objects.requireNonNull(ReflectionTestUtils.getField(cut, "jwtProcessors"))
        );

        ReflectionTestUtils.setField(cut, "jwtProcessors", jwtProcessors);
        return jwtProcessors;
    }
}
