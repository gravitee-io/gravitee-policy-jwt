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

import io.gravitee.policy.jwt.contentretriever.Content;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.observers.TestObserver;
import io.reactivex.rxjava3.plugins.RxJavaPlugins;
import io.reactivex.rxjava3.schedulers.TestScheduler;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCacheTest {

    private static final String REVOCATION_LIST_URL = "http://example.com/revocation-list";
    private static final int REFRESH_INTERVAL = 60;
    private static final String CONTENT_TYPE = "text/plain";

    @Mock
    private ContentRetriever contentRetriever;

    private RevocationCache revocationCache;

    @BeforeEach
    void setUp() {
        revocationCache = new RevocationCache(REVOCATION_LIST_URL, REFRESH_INTERVAL, contentRetriever);
        RevocationCache.cache.clear();
    }

    @Test
    void should_return_false_when_no_cached_values() {
        assertThat(revocationCache.contains("anyValue")).isFalse();
    }

    @Test
    void should_initialize_and_contain_revoked_values() {
        String content = "token1\ntoken2\n\ntoken3";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));

        revocationCache.initialize().blockingAwait();

        assertThat(revocationCache.contains("token1")).isTrue();
        assertThat(revocationCache.contains("token2")).isTrue();
        assertThat(revocationCache.contains("token3")).isTrue();
        assertThat(revocationCache.contains("token4")).isFalse();
    }

    @Test
    void should_handle_empty_content() {
        String content = "";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));

        revocationCache.initialize().blockingAwait();

        assertThat(revocationCache.contains("anyValue")).isFalse();
    }

    @Test
    void should_not_reload_when_already_initialized() {
        String content = "token1";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));
        revocationCache.initialize().blockingAwait();
        revocationCache.initialize().blockingAwait();

        verify(contentRetriever, times(1)).retrieve(REVOCATION_LIST_URL);
    }

    @Test
    void should_retry_initialization_with_exponential_backoff() {
        TestScheduler testScheduler = new TestScheduler();

        try {
            RxJavaPlugins.setComputationSchedulerHandler(scheduler -> testScheduler);

            // First two attempts fail, third succeeds
            when(contentRetriever.retrieve(REVOCATION_LIST_URL))
                .thenReturn(Single.error(new RuntimeException("First failure")))
                .thenReturn(Single.error(new RuntimeException("Second failure")))
                .thenReturn(Single.just(new Content("token1\ntoken2", CONTENT_TYPE)));

            // Start initialization
            TestObserver<Void> testObserver = revocationCache.initialize().test();

            // Initially should fail and schedule the first retry
            testObserver.assertNotComplete();
            verify(contentRetriever, times(1)).retrieve(REVOCATION_LIST_URL);

            // First retry after 5 seconds
            testScheduler.advanceTimeBy(5, TimeUnit.SECONDS);
            testObserver.assertNotComplete();
            verify(contentRetriever, times(2)).retrieve(REVOCATION_LIST_URL);

            // Second retry after 10 more seconds (15 total)
            testScheduler.advanceTimeBy(10, TimeUnit.SECONDS);

            // Should succeed after the third attempt
            testObserver.assertComplete();
            verify(contentRetriever, times(3)).retrieve(REVOCATION_LIST_URL);

            // Verify the content was eventually loaded
            assertThat(revocationCache.contains("token1")).isTrue();
            assertThat(revocationCache.contains("token2")).isTrue();
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void should_cap_retry_delay_at_maximum() {
        TestScheduler testScheduler = new TestScheduler();

        try {
            RxJavaPlugins.setComputationSchedulerHandler(scheduler -> testScheduler);

            // Always fail to test maximum delay capping
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.error(new RuntimeException("Always fails")));

            // Start initialization
            TestObserver<Void> testObserver = revocationCache.initialize().test();

            // Test progression through exponential backoff until max delay
            // Expected delays: 5, 10, 20, 40, 80, 160, 320, 640, 1280, then capped at 1800
            int[] expectedDelays = { 5, 10, 20, 40, 80, 160, 320, 640, 1280 };

            // Test exponential growth phase
            for (int i = 0; i < expectedDelays.length; i++) {
                testScheduler.triggerActions();
                verify(contentRetriever, times(i + 1)).retrieve(REVOCATION_LIST_URL);
                testObserver.assertNotComplete();

                testScheduler.advanceTimeBy(expectedDelays[i], TimeUnit.SECONDS);
            }

            // Test that delay is now capped at maximum (1800 seconds)
            // Next attempt should happen after 1800 seconds, not 2560 (which would be 1280 * 2)
            verify(contentRetriever, times(expectedDelays.length + 1)).retrieve(REVOCATION_LIST_URL);
            testObserver.assertNotComplete();

            // Advance by max delay (1800 seconds) - this should trigger the next retry
            testScheduler.advanceTimeBy(1800, TimeUnit.SECONDS);
            verify(contentRetriever, times(expectedDelays.length + 2)).retrieve(REVOCATION_LIST_URL);

            // Verify another attempt also uses max delay
            testScheduler.advanceTimeBy(1800, TimeUnit.SECONDS);
            verify(contentRetriever, times(expectedDelays.length + 3)).retrieve(REVOCATION_LIST_URL);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void should_trigger_background_refresh_when_cache_expired() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCachedList = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCachedList.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCachedList.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCachedList);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content("token2\ntoken3", CONTENT_TYPE)));

            assertThat(revocationCache.contains("token1")).isTrue();
            assertThat(revocationCache.contains("token2")).isTrue();
            assertThat(revocationCache.contains("token3")).isFalse();

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(contentRetriever).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCachedList, times(3)).isCacheExpired(REFRESH_INTERVAL);

            assertThat(revocationCache.contains("token1")).isFalse();
            assertThat(revocationCache.contains("token2")).isTrue();
            assertThat(revocationCache.contains("token3")).isTrue();
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void should_background_refresh_once_when_already_refreshing() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCache = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCache.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCache.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCache);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content("token2\ntoken3", CONTENT_TYPE)));

            for (int i = 0; i < 10; i++) {
                assertThat(revocationCache.contains("token1")).isTrue();
                assertThat(revocationCache.contains("token2")).isTrue();
            }

            testScheduler.triggerActions();

            verify(contentRetriever, times(1)).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCache, times(20)).isCacheExpired(REFRESH_INTERVAL);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void should_handle_error_during_background_refresh_keeping_old_values() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCachedList = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCachedList.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCachedList.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCachedList);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.error(new RuntimeException("Failed to refresh")));

            assertThat(revocationCache.contains("token1")).isTrue();
            assertThat(revocationCache.contains("token2")).isTrue();

            testScheduler.triggerActions();

            verify(contentRetriever).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCachedList, times(2)).isCacheExpired(REFRESH_INTERVAL);

            assertThat(revocationCache.contains("token1")).isTrue();
            assertThat(revocationCache.contains("token2")).isTrue();
        } finally {
            RxJavaPlugins.reset();
        }
    }
}
