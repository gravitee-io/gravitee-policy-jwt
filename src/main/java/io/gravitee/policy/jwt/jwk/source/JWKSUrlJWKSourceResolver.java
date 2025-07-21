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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import io.gravitee.policy.jwt.contentretriever.Content;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.schedulers.Schedulers;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Specific implementation of {@link JWKSource} allowing retrieve the JWKS from an url and triggering refresh every {@link #refreshInterval} in background.
 * If an error occurred during background refresh, previous version is kept to limit negative impacts.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWKSUrlJWKSourceResolver<C extends SecurityContext> implements JWKSource<C> {

    private static final Logger log = LoggerFactory.getLogger(JWKSUrlJWKSourceResolver.class);

    private final String jwksUrl;
    private final Duration refreshInterval;
    private final AtomicBoolean refreshing;
    private final ContentRetriever contentRetriever;

    /**
     * Global cache allowing to share jwk source across the whole platform and avoid re-loading the same JWKS url multiple times.
     */
    static final ConcurrentHashMap<String, CachedJWKSource<SecurityContext>> cache = new ConcurrentHashMap<>();

    public JWKSUrlJWKSourceResolver(String jwksUrl, ContentRetriever contentRetriever, Duration refreshInterval) {
        this.jwksUrl = jwksUrl;
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
            return load();
        }

        return Completable.complete();
    }

    private Completable load() {
        if (refreshing.compareAndSet(false, true)) {
            return contentRetriever
                .retrieve(jwksUrl)
                .flatMapMaybe(this::readJwkSourceFromResource)
                .map(CachedJWKSource::new)
                .doOnSuccess(jwkSource -> cache.put(jwksUrl, jwkSource))
                .doFinally(() -> refreshing.set(false))
                .ignoreElement();
        }

        return Completable.complete();
    }

    private void backgroundRefresh() {
        load()
            .subscribeOn(Schedulers.io())
            .subscribe(
                () -> log.debug("JWKS from url {} has been refreshed", jwksUrl),
                throwable ->
                    log.error(
                        "An error occurred when trying to background refresh the JWK from url {}. Previous JWKS kept untouched.",
                        jwksUrl,
                        throwable
                    )
            );
    }

    private Maybe<JWKSource<SecurityContext>> readJwkSourceFromResource(Content content) {
        try {
            JWKSet parsedJWKSet = JWKSet.parse(content.content());
            ImmutableJWKSet<SecurityContext> jwkSet = new ImmutableJWKSet<>(parsedJWKSet);
            return Maybe.just(jwkSet);
        } catch (ParseException e) {
            return Maybe.error(e);
        }
    }
}
