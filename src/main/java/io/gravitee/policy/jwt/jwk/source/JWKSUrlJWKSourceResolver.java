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

import static io.gravitee.common.http.HttpStatusCode.INTERNAL_SERVER_ERROR_500;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.policy.jwt.contentretriever.Content;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.schedulers.Schedulers;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.CustomLog;
import org.springframework.core.NestedExceptionUtils;

/**
 * Specific implementation of {@link JWKSource} allowing retrieve the JWKS from an url and triggering refresh every {@link #refreshInterval} in background.
 * If an error occurred during background refresh, previous version is kept to limit negative impacts.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@CustomLog
public class JWKSUrlJWKSourceResolver<C extends SecurityContext> implements JWKSource<C> {

    public static final String JWKS_RESOLUTION_ERROR_KEY = "JWT_JWKS_RESOLUTION_ERROR";

    private final String jwksUrl;
    private final RetrievalKey retrievalKey;
    private final Duration refreshInterval;
    private final AtomicBoolean refreshing;
    private final ContentRetriever contentRetriever;

    /**
     * Global cache allowing to share jwk source across the whole platform and avoid re-loading the same JWKS url multiple times.
     */
    static final ConcurrentHashMap<String, CachedJWKSource<SecurityContext>> cache = new ConcurrentHashMap<>();

    /**
     * How long a failed retrieval is remembered, so that repeated attempts fail fast instead of each waiting
     * for the connect / request timeout against an unreachable JWKS url.
     */
    static final Duration FAILURE_TTL = Duration.ofSeconds(10);

    /**
     * Upper bound of {@link #failures}. Once reached, further failures are not remembered until older ones expire.
     */
    static final int MAX_REMEMBERED_FAILURES = 1000;

    /**
     * Recent retrieval failures by jwks url and retrieval options, only relevant while no JWKS is cached for that url.
     */
    static final ConcurrentHashMap<RetrievalKey, FailedResolution> failures = new ConcurrentHashMap<>();

    /**
     * Retrievals in progress by jwks url and retrieval options, so that concurrent attempts share a single retrieval.
     */
    static final ConcurrentHashMap<RetrievalKey, Completable> loadings = new ConcurrentHashMap<>();

    /**
     * Identifies a retrieval: the same url fetched with other options (timeouts, proxy, redirects) may not fail the same way.
     */
    record RetrievalKey(String url, Integer connectTimeout, Long requestTimeout, Boolean useSystemProxy, Boolean followRedirects) {
        static RetrievalKey of(String url, RetrieveOptions options) {
            if (options == null) {
                return new RetrievalKey(url, null, null, null, null);
            }
            return new RetrievalKey(
                url,
                options.getConnectTimeout(),
                options.getRequestTimeout(),
                options.isUseSystemProxy(),
                options.isFollowRedirects()
            );
        }
    }

    record FailedResolution(long atNanos, ResolutionException error) {
        boolean isActive() {
            return System.nanoTime() - atNanos < FAILURE_TTL.toNanos();
        }
    }

    public JWKSUrlJWKSourceResolver(String jwksUrl, ContentRetriever contentRetriever, Duration refreshInterval) {
        this(jwksUrl, null, contentRetriever, refreshInterval);
    }

    public JWKSUrlJWKSourceResolver(
        String jwksUrl,
        RetrieveOptions retrieveOptions,
        ContentRetriever contentRetriever,
        Duration refreshInterval
    ) {
        this.jwksUrl = jwksUrl;
        this.retrievalKey = RetrievalKey.of(jwksUrl, retrieveOptions);
        this.refreshInterval = refreshInterval;
        this.refreshing = new AtomicBoolean(false);
        this.contentRetriever = contentRetriever;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        CachedJWKSource<SecurityContext> cachedJWKSource = cache.get(jwksUrl);

        if (cachedJWKSource != null) {
            if (cachedJWKSource.isCacheExpired(refreshInterval)) {
                backgroundRefresh();
            }

            return cachedJWKSource.get(jwkSelector, context);
        }

        return Collections.emptyList();
    }

    public Completable initialize() {
        CachedJWKSource<SecurityContext> cachedJWKSource = cache.get(jwksUrl);
        if (cachedJWKSource == null) {
            final FailedResolution failure = failures.get(retrievalKey);
            if (failure != null) {
                if (failure.isActive()) {
                    log.debug("JWKS from url {} failed to load recently, failing fast", jwksUrl);
                    return Completable.error(failure.error());
                }
                failures.remove(retrievalKey, failure);
            }
            return load();
        }

        return Completable.complete();
    }

    private Completable load() {
        return Completable.defer(() -> onCallerEventLoop(loadings.computeIfAbsent(retrievalKey, key -> retrieve())));
    }

    /**
     * A shared retrieval completes on the event loop of the request that started it: resume the other requests on their own.
     */
    private static Completable onCallerEventLoop(Completable retrieval) {
        final Context caller = Vertx.currentContext();
        if (caller == null || !caller.isEventLoopContext()) {
            return retrieval;
        }
        return retrieval.observeOn(Schedulers.from(command -> caller.runOnContext(ignored -> command.run())));
    }

    private Completable retrieve() {
        return contentRetriever
            .retrieve(jwksUrl)
            .onErrorResumeNext(throwable -> Single.error(new ResolutionException("Failed to retrieve JWKS from url " + jwksUrl, throwable)))
            .flatMapMaybe(this::readJwkSourceFromResource)
            .map(CachedJWKSource::new)
            .doOnSuccess(jwkSource -> cache.put(jwksUrl, jwkSource))
            .doOnError(this::onLoadError)
            .ignoreElement()
            .doFinally(() -> loadings.remove(retrievalKey))
            .cache();
    }

    private void onLoadError(Throwable throwable) {
        if (cache.containsKey(jwksUrl)) {
            if (log.isWarnEnabled()) {
                log.warn("Unable to refresh the JWKS from url {}, previous JWKS kept untouched: {}", jwksUrl, describe(throwable));
            }
            return;
        }

        if (log.isWarnEnabled()) {
            log.warn("Unable to load the JWKS from url {}: {}", jwksUrl, describe(throwable));
        }
        if (throwable instanceof ResolutionException resolutionException) {
            rememberFailure(resolutionException);
        }
    }

    private static String describe(Throwable throwable) {
        return throwable.getCause() == null ? throwable.getMessage() : withMostSpecificCause(throwable.getMessage(), throwable.getCause());
    }

    private static String withMostSpecificCause(String message, Throwable cause) {
        final Throwable mostSpecific = NestedExceptionUtils.getMostSpecificCause(cause);
        final String mostSpecificMessage = Optional.ofNullable(mostSpecific.getMessage()).map(String::trim).orElse("");
        return mostSpecificMessage.isEmpty() ? message : message + " - " + mostSpecificMessage;
    }

    private void rememberFailure(ResolutionException error) {
        if (failures.size() >= MAX_REMEMBERED_FAILURES) {
            failures.values().removeIf(failure -> !failure.isActive());
        }
        if (failures.size() < MAX_REMEMBERED_FAILURES) {
            failures.put(retrievalKey, new FailedResolution(System.nanoTime(), error.withoutCause()));
        }
    }

    private void backgroundRefresh() {
        if (refreshing.compareAndSet(false, true)) {
            load()
                .doFinally(() -> refreshing.set(false))
                .subscribeOn(Schedulers.io())
                .subscribe(
                    () -> log.debug("JWKS from url {} has been refreshed", jwksUrl),
                    throwable -> log.debug("Background refresh of the JWKS from url {} failed", jwksUrl, throwable)
                );
        }
    }

    private Maybe<JWKSource<SecurityContext>> readJwkSourceFromResource(Content content) {
        try {
            JWKSet parsedJWKSet = JWKSet.parse(content.content());
            ImmutableJWKSet<SecurityContext> jwkSet = new ImmutableJWKSet<>(parsedJWKSet);
            return Maybe.just(jwkSet);
        } catch (ParseException e) {
            return Maybe.error(new ResolutionException("Failed to parse JWKS retrieved from url " + jwksUrl, e));
        }
    }

    public static final class ResolutionException extends RuntimeException {

        private final String failureMessage;

        public ResolutionException(String message, Throwable cause) {
            super(message, cause);
            this.failureMessage = withMostSpecificCause(message, cause);
        }

        private ResolutionException(String message, String failureMessage) {
            super(message, null, false, false);
            this.failureMessage = failureMessage;
        }

        /**
         * Same message and execution failure, without the cause chain and stack trace, so it is cheap to keep and to share.
         */
        ResolutionException withoutCause() {
            return new ResolutionException(getMessage(), failureMessage);
        }

        /**
         * A new execution failure on each call, since the same exception can be handed to several requests.
         */
        public ExecutionFailure failure() {
            return new ExecutionFailure(INTERNAL_SERVER_ERROR_500)
                .key(JWKS_RESOLUTION_ERROR_KEY)
                .message(HttpResponseStatus.INTERNAL_SERVER_ERROR.reasonPhrase())
                .cause(new RuntimeException(failureMessage));
        }
    }
}
