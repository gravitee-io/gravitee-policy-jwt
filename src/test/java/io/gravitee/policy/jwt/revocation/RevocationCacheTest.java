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
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.plugins.RxJavaPlugins;
import io.reactivex.rxjava3.schedulers.TestScheduler;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
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
    void shouldReturnEmptySetWhenNoCachedValues() {
        Set<String> revokedValues = revocationCache.getRevokedValues();

        assertThat(revokedValues).isEmpty();
    }

    @Test
    void shouldInitializeAndParseRevokedValues() {
        String content = "token1\ntoken2\n\ntoken3";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));

        revocationCache.initialize().blockingAwait();

        Set<String> revokedValues = revocationCache.getRevokedValues();
        assertThat(revokedValues).hasSize(3).contains("token1", "token2", "token3");
    }

    @Test
    void shouldHandleEmptyContent() {
        String content = "";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));

        revocationCache.initialize().blockingAwait();

        Set<String> revokedValues = revocationCache.getRevokedValues();
        assertThat(revokedValues).isEmpty();
    }

    @Test
    void shouldNotReloadWhenAlreadyInitialized() {
        String content = "token1";
        when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content(content, CONTENT_TYPE)));
        revocationCache.initialize().blockingAwait();
        revocationCache.initialize().blockingAwait();

        verify(contentRetriever, times(1)).retrieve(REVOCATION_LIST_URL);
    }

    @Test
    void shouldTriggerBackgroundRefreshWhenCacheExpired() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCachedList = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            // Background refresh is made on IO schedulers, fake it to get fine control.
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCachedList.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCachedList.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCachedList);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content("token2\ntoken3", CONTENT_TYPE)));

            Set<String> valuesBeforeRefresh = revocationCache.getRevokedValues();
            assertThat(valuesBeforeRefresh).hasSize(2).contains("token1", "token2");

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(contentRetriever).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCachedList).isCacheExpired(REFRESH_INTERVAL);

            Set<String> refreshedValues = revocationCache.getRevokedValues();
            assertThat(refreshedValues).hasSize(2).contains("token2", "token3");
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldBackgroundRefreshOnceWhenAlreadyRefreshing() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCache = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            // Background refresh is made on IO schedulers, fake it to get fine control.
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCache.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCache.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCache);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.just(new Content("token2\ntoken3", CONTENT_TYPE)));

            // Make multiple calls while cache is expired.
            for (int i = 0; i < 10; i++) {
                Set<String> values = revocationCache.getRevokedValues();
                assertThat(values).hasSize(2).contains("token1", "token2");
            }

            testScheduler.triggerActions();

            // Only 1 background refresh occurred.
            verify(contentRetriever, times(1)).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCache, times(10)).isCacheExpired(REFRESH_INTERVAL);
        } finally {
            RxJavaPlugins.reset();
        }
    }

    @Test
    void shouldHandleErrorDuringBackgroundRefreshKeepingOldValues() {
        TestScheduler testScheduler = new TestScheduler();
        CachedRevocationList mockedExpiredCachedList = mock(CachedRevocationList.class);
        Set<String> oldValues = new HashSet<>(Arrays.asList("token1", "token2"));

        try {
            // Background refresh is made on IO schedulers, fake it to get fine control.
            RxJavaPlugins.setIoSchedulerHandler(scheduler -> testScheduler);

            when(mockedExpiredCachedList.getRevokedValues()).thenReturn(oldValues);
            when(mockedExpiredCachedList.isCacheExpired(REFRESH_INTERVAL)).thenReturn(true);
            RevocationCache.cache.put(REVOCATION_LIST_URL, mockedExpiredCachedList);
            when(contentRetriever.retrieve(REVOCATION_LIST_URL)).thenReturn(Single.error(new RuntimeException("Failed to refresh")));

            Set<String> valuesBeforeRefresh = revocationCache.getRevokedValues();
            assertThat(valuesBeforeRefresh).hasSize(2).contains("token1", "token2");

            testScheduler.triggerActions();

            // Background refresh occurred.
            verify(contentRetriever).retrieve(REVOCATION_LIST_URL);
            verify(mockedExpiredCachedList).isCacheExpired(REFRESH_INTERVAL);

            // Previous cached values retained
            Set<String> valuesAfterFailedRefresh = revocationCache.getRevokedValues();
            assertThat(valuesAfterFailedRefresh).hasSize(2).contains("token1", "token2");
        } finally {
            RxJavaPlugins.reset();
        }
    }
}
