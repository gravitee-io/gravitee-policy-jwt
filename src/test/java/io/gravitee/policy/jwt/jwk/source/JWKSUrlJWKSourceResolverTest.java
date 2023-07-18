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
package io.gravitee.policy.jwt.jwk.source;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.jwk.AbstractJWKTest;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.observers.TestObserver;
import io.reactivex.rxjava3.plugins.RxJavaPlugins;
import io.reactivex.rxjava3.schedulers.TestScheduler;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class JWKSUrlJWKSourceResolverTest extends AbstractJWKTest {

    protected static final String JWKS_URL = "https://gravitee.io/.well-known/{type}/jwks.json";

    protected static final Duration REFRESH_INTERVAL = Duration.ofMinutes(5);
    protected static final String MOCK_EXCEPTION = "Mock exception";

    @Mock
    private ResourceRetriever resourceRetriever;

    private String jwksUrl;

    private JWKSUrlJWKSourceResolver<SecurityContext> cut;

    @BeforeEach
    void init() {
        JWKSUrlJWKSourceResolver.cache.clear();

        jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, resourceRetriever, REFRESH_INTERVAL);
    }

    @Test
    void shouldLoadAndCacheWhenFirstInitialize() {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final Resource resource = new Resource(generateJWKS(), "application/json");

        when(resourceRetriever.retrieve(jwksUrl)).thenReturn(Single.just(resource));

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, resourceRetriever, REFRESH_INTERVAL);
        final TestObserver<Void> obs = cut.initialize().test();
        obs.assertComplete();

        final CachedJWKSource<SecurityContext> cachedJWKSource = JWKSUrlJWKSourceResolver.cache.get(jwksUrl);
        assertNotNull(cachedJWKSource);
        assertNotNull(cachedJWKSource.getCacheDateTime());
    }

    @Test
    void shouldNotLoadAndGetFromCacheWhenInitializeAndAlreadyCached() {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);

        JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, resourceRetriever, REFRESH_INTERVAL);
        final TestObserver<Void> obs = cut.initialize().test();
        obs.assertComplete();

        verifyNoInteractions(resourceRetriever);
    }

    @Test
    void shouldGetFromCacheWhenGetJWKListAndAlreadyCached() throws KeySourceException {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);
        final JWKSelector jwkSelector = mock(JWKSelector.class);
        final List<JWK> jwkList = Collections.emptyList();

        when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
        JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
        when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(false);

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, resourceRetriever, REFRESH_INTERVAL);

        assertEquals(jwkList, cut.get(jwkSelector, null));
        verifyNoInteractions(resourceRetriever);
    }

    @Test
    void shouldGetFromCacheAndBackgroundRefreshWhenGetCacheExpired() throws KeySourceException {
        try {
            final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
            final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);
            final JWKSelector jwkSelector = mock(JWKSelector.class);
            final List<JWK> jwkList = Collections.emptyList();
            final Resource resource = new Resource(generateJWKS(), "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(resourceRetriever.retrieve(jwksUrl)).thenReturn(Single.just(resource));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                resourceRetriever,
                REFRESH_INTERVAL
            );

            // Previous cache is returned.
            assertEquals(jwkList, cut.get(jwkSelector, null));

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(resourceRetriever).retrieve(jwksUrl);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldBackgroundRefreshOnceWhenAlreadyInBackgroundRefresh() throws KeySourceException {
        try {
            final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
            final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);
            final JWKSelector jwkSelector = mock(JWKSelector.class);
            final List<JWK> jwkList = Collections.emptyList();
            final Resource resource = new Resource(generateJWKS(), "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(resourceRetriever.retrieve(jwksUrl)).thenReturn(Single.just(resource));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                resourceRetriever,
                REFRESH_INTERVAL
            );

            // Make multiple calls while cache is expired.
            for (int i = 0; i < 10; i++) {
                assertEquals(jwkList, cut.get(jwkSelector, null));
            }

            testScheduler.triggerActions();

            // Only 1 background refresh occurred.
            verify(resourceRetriever, times(1)).retrieve(jwksUrl);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldSilentlyLogErrorWhenErrorOccurredDuringBackgroundRefresh() throws KeySourceException {
        try {
            final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
            final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);
            final JWKSelector jwkSelector = mock(JWKSelector.class);
            final List<JWK> jwkList = Collections.emptyList();
            final Resource resource = new Resource("BAD JWKS", "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            when(resourceRetriever.retrieve(jwksUrl)).thenReturn(Single.just(resource));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                resourceRetriever,
                REFRESH_INTERVAL
            );

            // List of keys is returned.
            assertEquals(jwkList, cut.get(jwkSelector, null));

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(resourceRetriever, times(1)).retrieve(jwksUrl);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldReturnEmptyWhenNullCache() throws KeySourceException {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSelector jwkSelector = mock(JWKSelector.class);

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, resourceRetriever, REFRESH_INTERVAL);

        assertEquals(Collections.emptyList(), cut.get(jwkSelector, null));
        verifyNoInteractions(resourceRetriever);
    }

    private String generateJWKS() {
        final KeyPair keyPair = generateKeyPair(2048, Signature.RSA_RS256.getAlg());
        final RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey(keyPair.getPrivate())
            .keyID("key1")
            .algorithm(Signature.RSA_RS256.getAlg())
            .build();

        return new JWKSet(rsaKey).toString();
    }
}
