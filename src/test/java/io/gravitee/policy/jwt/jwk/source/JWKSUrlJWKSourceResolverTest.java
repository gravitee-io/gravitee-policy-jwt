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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.contentretriever.Content;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.gravitee.policy.jwt.jwk.AbstractJWKTest;
import io.gravitee.policy.jwt.jwk.source.JWKSUrlJWKSourceResolver.RetrievalKey;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.observers.TestObserver;
import io.reactivex.rxjava3.plugins.RxJavaPlugins;
import io.reactivex.rxjava3.schedulers.TestScheduler;
import io.reactivex.rxjava3.subjects.SingleSubject;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Context;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.ThreadingModel;
import io.vertx.core.Vertx;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

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
    private ContentRetriever contentRetriever;

    private String jwksUrl;

    private JWKSUrlJWKSourceResolver<SecurityContext> cut;

    @BeforeEach
    void init() {
        JWKSUrlJWKSourceResolver.cache.clear();
        JWKSUrlJWKSourceResolver.failures.clear();
        JWKSUrlJWKSourceResolver.loadings.clear();

        jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);
    }

    @Test
    void shouldLoadAndCacheWhenFirstInitialize() {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final Content content = new Content(generateJWKS(), "application/json");

        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(content));

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);
        final TestObserver<Void> obs = cut.initialize().test();
        obs.assertComplete();

        final CachedJWKSource<SecurityContext> cachedJWKSource = JWKSUrlJWKSourceResolver.cache.get(jwksUrl);
        assertNotNull(cachedJWKSource);
        assertNotNull(cachedJWKSource.getCacheDateTime());
    }

    @Test
    void shouldFailFastWithoutRetrievingWhenRecentFailureRemembered() {
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));

        cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);

        // A new resolver (as built for each request) must not hit the unreachable url again.
        final JWKSUrlJWKSourceResolver<SecurityContext> other = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);
        for (int i = 0; i < 5; i++) {
            other.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);
        }

        verify(contentRetriever, times(1)).retrieve(jwksUrl);
    }

    @Test
    void shouldRetryRetrievingAndForgetFailureWhenRememberedFailureExpired() {
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));
        cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);

        expireRememberedFailure(jwksUrl);

        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(new Content(generateJWKS(), "application/json")));
        cut.initialize().test().assertComplete();

        verify(contentRetriever, times(2)).retrieve(jwksUrl);
        assertNotNull(JWKSUrlJWKSourceResolver.cache.get(jwksUrl));
        assertThat(JWKSUrlJWKSourceResolver.failures).doesNotContainKey(keyOf(jwksUrl));
    }

    @Test
    void shouldRememberFailureWithoutCauseNorStackTrace() {
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));
        final Completable initialization = cut.initialize();

        final JWKSUrlJWKSourceResolver.ResolutionException original = assertThrows(
            JWKSUrlJWKSourceResolver.ResolutionException.class,
            initialization::blockingAwait
        );
        final JWKSUrlJWKSourceResolver.ResolutionException remembered = JWKSUrlJWKSourceResolver.failures.get(keyOf(jwksUrl)).error();
        assertThat(original.getCause()).isNotNull();
        assertThat(remembered.getCause()).isNull();
        assertThat(remembered.getStackTrace()).isEmpty();
        assertThat(remembered.getMessage()).isEqualTo(original.getMessage());
        assertThat(remembered.failure().key()).isEqualTo(original.failure().key());
        assertThat(remembered.failure().cause()).hasMessage(original.failure().cause().getMessage());
    }

    @Test
    void shouldBuildNewExecutionFailureOnEachCall() {
        final JWKSUrlJWKSourceResolver.ResolutionException error = new JWKSUrlJWKSourceResolver.ResolutionException(
            "Failed",
            new RuntimeException(MOCK_EXCEPTION)
        ).withoutCause();

        assertThat(error.failure()).isNotSameAs(error.failure());
        assertThat(error.failure().key()).isEqualTo(JWKSUrlJWKSourceResolver.JWKS_RESOLUTION_ERROR_KEY);
        assertThat(error.failure().statusCode()).isEqualTo(500);
        assertThat(error.failure().cause()).hasMessage("Failed - " + MOCK_EXCEPTION);
    }

    static Stream<Arguments> retrievalOptionsThatDifferByOneOption() {
        return Stream.of(
            Arguments.of(RetrieveOptions.builder().connectTimeout(500).build(), RetrieveOptions.builder().connectTimeout(5000).build()),
            Arguments.of(RetrieveOptions.builder().requestTimeout(500L).build(), RetrieveOptions.builder().requestTimeout(5000L).build()),
            Arguments.of(RetrieveOptions.builder().useSystemProxy(false).build(), RetrieveOptions.builder().useSystemProxy(true).build()),
            Arguments.of(RetrieveOptions.builder().followRedirects(false).build(), RetrieveOptions.builder().followRedirects(true).build())
        );
    }

    @ParameterizedTest
    @MethodSource("retrievalOptionsThatDifferByOneOption")
    void shouldNotShareRememberedFailureBetweenRetrievalOptions(RetrieveOptions oneOptions, RetrieveOptions otherOptions) {
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));

        new JWKSUrlJWKSourceResolver<>(jwksUrl, oneOptions, contentRetriever, REFRESH_INTERVAL)
            .initialize()
            .test()
            .assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);
        new JWKSUrlJWKSourceResolver<>(jwksUrl, otherOptions, contentRetriever, REFRESH_INTERVAL)
            .initialize()
            .test()
            .assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);
        verify(contentRetriever, times(2)).retrieve(jwksUrl);

        new JWKSUrlJWKSourceResolver<>(jwksUrl, oneOptions, contentRetriever, REFRESH_INTERVAL)
            .initialize()
            .test()
            .assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);
        verify(contentRetriever, times(2)).retrieve(jwksUrl);
    }

    @Test
    void shouldNotShareRetrievalInProgressBetweenRetrievalOptions() {
        final SingleSubject<Content> retrieval = SingleSubject.create();
        final AtomicInteger subscriptions = new AtomicInteger();
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(retrieval.doOnSubscribe(d -> subscriptions.incrementAndGet()));

        final TestObserver<Void> first = new JWKSUrlJWKSourceResolver<>(
            jwksUrl,
            RetrieveOptions.builder().followRedirects(false).build(),
            contentRetriever,
            REFRESH_INTERVAL
        )
            .initialize()
            .test();
        final TestObserver<Void> second = new JWKSUrlJWKSourceResolver<>(
            jwksUrl,
            RetrieveOptions.builder().followRedirects(true).build(),
            contentRetriever,
            REFRESH_INTERVAL
        )
            .initialize()
            .test();

        assertThat(subscriptions).hasValue(2);
        assertThat(JWKSUrlJWKSourceResolver.loadings).hasSize(2);
        retrieval.onSuccess(new Content(generateJWKS(), "application/json"));
        first.assertComplete();
        second.assertComplete();
    }

    @Test
    void shouldResumeJoiningInitializationOnItsOwnEventLoop() throws Exception {
        final Vertx vertx = Vertx.vertx();
        try {
            final SingleSubject<Content> retrieval = SingleSubject.create();
            when(contentRetriever.retrieve(jwksUrl)).thenReturn(retrieval);
            final Context starter = newContext(vertx);
            final Context joiner = newContext(vertx);
            assertThat(joiner).isNotSameAs(starter);
            final CompletableFuture<Context> starterResumedOn = new CompletableFuture<>();
            final CompletableFuture<Context> joinerResumedOn = new CompletableFuture<>();
            final CompletableFuture<Void> joined = new CompletableFuture<>();

            starter.runOnContext(v ->
                cut.initialize().subscribe(() -> starterResumedOn.complete(Vertx.currentContext()), starterResumedOn::completeExceptionally)
            );
            joiner.runOnContext(v -> {
                new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL)
                    .initialize()
                    .subscribe(() -> joinerResumedOn.complete(Vertx.currentContext()), joinerResumedOn::completeExceptionally);
                joined.complete(null);
            });
            joined.get(5, TimeUnit.SECONDS);
            starter.runOnContext(v -> retrieval.onSuccess(new Content(generateJWKS(), "application/json")));

            assertThat(starterResumedOn.get(5, TimeUnit.SECONDS)).isSameAs(starter);
            assertThat(joinerResumedOn.get(5, TimeUnit.SECONDS)).isSameAs(joiner);
            verify(contentRetriever, times(1)).retrieve(jwksUrl);
        } finally {
            vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void shouldNotRememberFailureWhenTooManyRecentFailures() {
        for (int i = 0; i < JWKSUrlJWKSourceResolver.MAX_REMEMBERED_FAILURES; i++) {
            JWKSUrlJWKSourceResolver.failures.put(keyOf("https://other/" + i), rememberedFailure(System.nanoTime()));
        }
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));

        cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);
        cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);

        verify(contentRetriever, times(2)).retrieve(jwksUrl);
        assertThat(JWKSUrlJWKSourceResolver.failures)
            .hasSize(JWKSUrlJWKSourceResolver.MAX_REMEMBERED_FAILURES)
            .doesNotContainKey(keyOf(jwksUrl));
    }

    @Test
    void shouldEvictExpiredFailuresWhenTooManyFailures() {
        final long expired = System.nanoTime() - Duration.ofMinutes(5).toNanos();
        for (int i = 0; i < JWKSUrlJWKSourceResolver.MAX_REMEMBERED_FAILURES; i++) {
            JWKSUrlJWKSourceResolver.failures.put(keyOf("https://other/" + i), rememberedFailure(expired));
        }
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));

        cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);

        assertThat(JWKSUrlJWKSourceResolver.failures).containsOnlyKeys(keyOf(jwksUrl));
    }

    @Test
    void shouldShareOneRetrievalBetweenConcurrentInitializations() {
        final SingleSubject<Content> retrieval = SingleSubject.create();
        final AtomicInteger subscriptions = new AtomicInteger();
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(
            Single.defer(() -> retrieval).doOnSubscribe(d -> subscriptions.incrementAndGet())
        );

        final TestObserver<Void> first = cut.initialize().test();
        final TestObserver<Void> second = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL).initialize().test();
        first.assertNotComplete();
        second.assertNotComplete();

        retrieval.onSuccess(new Content(generateJWKS(), "application/json"));

        first.assertComplete();
        second.assertComplete();
        assertThat(subscriptions).hasValue(1);
        verify(contentRetriever, times(1)).retrieve(jwksUrl);
        assertThat(JWKSUrlJWKSourceResolver.loadings).isEmpty();
    }

    @Test
    void shouldNotResumeOnWorkerContextThatAwaitsTheRetrieval() throws Exception {
        final Vertx vertx = Vertx.vertx();
        try {
            final SingleSubject<Content> retrieval = SingleSubject.create();
            final CountDownLatch subscribed = new CountDownLatch(1);
            when(contentRetriever.retrieve(jwksUrl)).thenReturn(retrieval.doOnSubscribe(d -> subscribed.countDown()));
            final CompletableFuture<Context> workerContext = new CompletableFuture<>();
            vertx.deployVerticle(
                new AbstractVerticle() {
                    @Override
                    public void start() {
                        workerContext.complete(context);
                    }
                },
                new DeploymentOptions().setThreadingModel(ThreadingModel.WORKER)
            );
            final CompletableFuture<Boolean> completed = new CompletableFuture<>();

            workerContext
                .get(5, TimeUnit.SECONDS)
                .runOnContext(v -> completed.complete(cut.initialize().blockingAwait(2, TimeUnit.SECONDS)));
            assertThat(subscribed.await(5, TimeUnit.SECONDS)).isTrue();
            retrieval.onSuccess(new Content(generateJWKS(), "application/json"));

            assertThat(completed.get(5, TimeUnit.SECONDS)).isTrue();
        } finally {
            vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void shouldLogWarningWhenRetrievalFails() {
        final Logger logger = (Logger) LoggerFactory.getLogger(JWKSUrlJWKSourceResolver.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));

            cut.initialize().test().assertError(JWKSUrlJWKSourceResolver.ResolutionException.class);

            assertThat(appender.list)
                .filteredOn(event -> event.getLevel() == Level.WARN)
                .singleElement()
                .extracting(ILoggingEvent::getFormattedMessage)
                .asString()
                .contains("Unable to load the JWKS from url " + jwksUrl)
                .contains(MOCK_EXCEPTION);
        } finally {
            logger.detachAppender(appender);
        }
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = { "", "   " })
    void shouldKeepResolutionMessageWhenRootCauseHasNoMessage(String rootCauseMessage) {
        final String resolutionMessage = "Failed to retrieve JWKS from url " + jwksUrl;
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.error(new RuntimeException(rootCauseMessage)));

        final List<String> warnings = warningsLoggedWhile(() ->
            cut
                .initialize()
                .test()
                .assertError(
                    error ->
                        error instanceof JWKSUrlJWKSourceResolver.ResolutionException resolutionException &&
                        resolutionMessage.equals(resolutionException.failure().cause().getMessage())
                )
        );

        assertThat(warnings).containsExactly("Unable to load the JWKS from url " + jwksUrl + ": " + resolutionMessage);
    }

    @Test
    void shouldLogMessageOfErrorWithoutCauseWhenLoadingFails() {
        final Content content = mock(Content.class);
        when(content.content()).thenThrow(new IllegalStateException("Unreadable content"));
        when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(content));

        final List<String> warnings = warningsLoggedWhile(() -> cut.initialize().test().assertError(IllegalStateException.class));

        assertThat(warnings).containsExactly("Unable to load the JWKS from url " + jwksUrl + ": Unreadable content");
        assertThat(JWKSUrlJWKSourceResolver.failures).isEmpty();
    }

    private static List<String> warningsLoggedWhile(Runnable action) {
        final Logger logger = (Logger) LoggerFactory.getLogger(JWKSUrlJWKSourceResolver.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list
            .stream()
            .filter(event -> event.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    }

    @Test
    void shouldNotLoadAndGetFromCacheWhenInitializeAndAlreadyCached() {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);

        JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);
        final TestObserver<Void> obs = cut.initialize().test();
        obs.assertComplete();

        verifyNoInteractions(contentRetriever);
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

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);

        assertEquals(jwkList, cut.get(jwkSelector, null));
        verifyNoInteractions(contentRetriever);
    }

    @Test
    void shouldGetFromCacheAndBackgroundRefreshWhenGetCacheExpired() throws KeySourceException {
        try {
            final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
            final CachedJWKSource<SecurityContext> jwkSource = mock(CachedJWKSource.class);
            final JWKSelector jwkSelector = mock(JWKSelector.class);
            final List<JWK> jwkList = Collections.emptyList();
            final Content content = new Content(generateJWKS(), "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(content));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                contentRetriever,
                REFRESH_INTERVAL
            );

            // Previous cache is returned.
            assertEquals(jwkList, cut.get(jwkSelector, null));

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(contentRetriever).retrieve(jwksUrl);
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
            final Content content = new Content(generateJWKS(), "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(content));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                contentRetriever,
                REFRESH_INTERVAL
            );

            // Make multiple calls while cache is expired.
            for (int i = 0; i < 10; i++) {
                assertEquals(jwkList, cut.get(jwkSelector, null));
            }

            testScheduler.triggerActions();

            // Only 1 background refresh occurred.
            verify(contentRetriever, times(1)).retrieve(jwksUrl);

            // Once that refresh is over, the next expiry triggers a new one.
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);
            assertEquals(jwkList, cut.get(jwkSelector, null));
            testScheduler.triggerActions();
            verify(contentRetriever, times(2)).retrieve(jwksUrl);
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
            final Content content = new Content("BAD JWKS", "application/json");

            when(jwkSource.get(jwkSelector, null)).thenReturn(jwkList);
            when(jwkSource.isCacheExpired(any(Duration.class))).thenReturn(true);

            when(contentRetriever.retrieve(jwksUrl)).thenReturn(Single.just(content));
            JWKSUrlJWKSourceResolver.cache.put(jwksUrl, jwkSource);

            // Background refresh is made on IO schedulers, fake it to get fine control.
            final TestScheduler testScheduler = new TestScheduler();
            RxJavaPlugins.setIoSchedulerHandler(ignore -> testScheduler);

            final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(
                jwksUrl,
                contentRetriever,
                REFRESH_INTERVAL
            );

            final Logger logger = (Logger) LoggerFactory.getLogger(JWKSUrlJWKSourceResolver.class);
            final ListAppender<ILoggingEvent> appender = new ListAppender<>();
            appender.start();
            logger.addAppender(appender);
            try {
                // List of keys is returned.
                assertEquals(jwkList, cut.get(jwkSelector, null));

                testScheduler.triggerActions();
            } finally {
                logger.detachAppender(appender);
            }

            // Background refresh occurred, and its failure is not remembered since a JWKS is still cached.
            verify(contentRetriever, times(1)).retrieve(jwksUrl);
            assertThat(JWKSUrlJWKSourceResolver.failures).isEmpty();
            assertThat(appender.list)
                .filteredOn(event -> event.getLevel() == Level.WARN)
                .singleElement()
                .extracting(ILoggingEvent::getFormattedMessage)
                .asString()
                .contains("Unable to refresh the JWKS from url " + jwksUrl)
                .contains("Failed to parse JWKS retrieved from url " + jwksUrl);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldReturnEmptyWhenNullCache() throws KeySourceException {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSelector jwkSelector = mock(JWKSelector.class);

        final JWKSUrlJWKSourceResolver<SecurityContext> cut = new JWKSUrlJWKSourceResolver<>(jwksUrl, contentRetriever, REFRESH_INTERVAL);

        assertEquals(Collections.emptyList(), cut.get(jwkSelector, null));
        verifyNoInteractions(contentRetriever);
    }

    /**
     * A context created from its own thread, since a thread outside Vert.x may keep reusing the same context.
     */
    private static Context newContext(Vertx vertx) throws Exception {
        final CompletableFuture<Context> context = new CompletableFuture<>();
        final Thread thread = new Thread(() -> context.complete(vertx.getOrCreateContext()));
        thread.start();
        thread.join();
        return context.get();
    }

    private static RetrievalKey keyOf(String url) {
        return RetrievalKey.of(url, null);
    }

    private static void expireRememberedFailure(String url) {
        final JWKSUrlJWKSourceResolver.FailedResolution failure = JWKSUrlJWKSourceResolver.failures.get(keyOf(url));
        JWKSUrlJWKSourceResolver.failures.put(
            keyOf(url),
            new JWKSUrlJWKSourceResolver.FailedResolution(System.nanoTime() - Duration.ofMinutes(5).toNanos(), failure.error())
        );
    }

    private static JWKSUrlJWKSourceResolver.FailedResolution rememberedFailure(long atNanos) {
        return new JWKSUrlJWKSourceResolver.FailedResolution(
            atNanos,
            new JWKSUrlJWKSourceResolver.ResolutionException("Failed", new RuntimeException(MOCK_EXCEPTION)).withoutCause()
        );
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
