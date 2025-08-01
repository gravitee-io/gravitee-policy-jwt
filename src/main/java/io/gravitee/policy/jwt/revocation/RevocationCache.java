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

import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Flowable;
import io.reactivex.rxjava3.schedulers.Schedulers;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RevocationCache {

    private static final int INITIALIZE_RETRY_INITIAL_DELAY_SECONDS = 5;
    private static final int INITIALIZE_RETRY_MAX_DELAY_SECONDS = 1800; //30 mins

    private final String revocationListUrl;
    private final int refreshInterval;
    //Instance locking for cache update
    private final AtomicBoolean refreshing;
    private final ContentRetriever contentRetriever;

    /**
     * Global cache allowing to share revocation lists across the platform and avoid re-loading the same revocation list url multiple times.
     */
    static final ConcurrentHashMap<String, CachedRevocationList> cache = new ConcurrentHashMap<>();

    public RevocationCache(String revocationListUrl, int refreshInterval, ContentRetriever contentRetriever) {
        this.revocationListUrl = revocationListUrl;
        this.refreshInterval = refreshInterval;
        this.refreshing = new AtomicBoolean(false);
        this.contentRetriever = contentRetriever;
    }

    public boolean contains(String value) {
        return getRevokedValues().contains(value);
    }

    public Completable initialize() {
        CachedRevocationList cachedRevocationList = cache.get(revocationListUrl);
        if (cachedRevocationList == null) {
            return loadWithRetry();
        }

        return Completable.complete();
    }

    private Set<String> getRevokedValues() {
        CachedRevocationList cachedRevocationList = cache.get(revocationListUrl);

        if (cachedRevocationList == null) {
            log.warn("No cached revocation list found. Revocation check will be skipped.");
            return Collections.emptySet();
        }

        if (cachedRevocationList.isCacheExpired(refreshInterval)) {
            backgroundRefresh();
        }

        return cachedRevocationList.getRevokedValues();
    }

    private Completable loadWithRetry() {
        AtomicInteger retryCount = new AtomicInteger(0);
        return Completable
            .defer(this::load)
            .retryWhen(errors ->
                errors
                    .map(error -> {
                        int attempt = retryCount.incrementAndGet();
                        int delaySeconds = Math.min(
                            INITIALIZE_RETRY_INITIAL_DELAY_SECONDS * (1 << (attempt - 1)),
                            INITIALIZE_RETRY_MAX_DELAY_SECONDS
                        );
                        log.warn(
                            "Failed to initialize revocation cache (attempt {}), retrying in {} seconds",
                            attempt,
                            delaySeconds,
                            error
                        );
                        return delaySeconds;
                    })
                    .flatMap(delay -> Flowable.timer(delay, TimeUnit.SECONDS, Schedulers.computation()))
            );
    }

    private Completable load() {
        if (refreshing.compareAndSet(false, true)) {
            return this.contentRetriever.retrieve(revocationListUrl)
                .map(content -> new CachedRevocationList(parseRevokedValues(content.content())))
                .doOnSuccess(cachedList -> cache.put(revocationListUrl, cachedList))
                .doFinally(() -> refreshing.set(false))
                .ignoreElement();
        }

        return Completable.complete();
    }

    private void backgroundRefresh() {
        load()
            .subscribeOn(Schedulers.io())
            .subscribe(
                () -> log.info("Revocation list from url {} has been refreshed", revocationListUrl),
                throwable ->
                    log.error(
                        "An error occurred when trying to background refresh the revocation list from url {}. Previous revocation list kept untouched.",
                        revocationListUrl,
                        throwable
                    )
            );
    }

    private Set<String> parseRevokedValues(String content) {
        try {
            if (content == null) {
                log.warn("Received null content for revocation list, setting empty revocation list");
                return Collections.emptySet();
            }

            return Arrays.stream(content.split("\n")).map(String::trim).filter(line -> !line.isEmpty()).collect(Collectors.toSet());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse revocation list content", e);
        }
    }
}
