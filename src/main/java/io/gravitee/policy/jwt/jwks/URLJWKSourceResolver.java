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
package io.gravitee.policy.jwt.jwks;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import io.gravitee.el.TemplateEngine;
import io.gravitee.policy.jwt.jwks.retriever.ResourceRetriever;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class URLJWKSourceResolver<C extends SecurityContext> implements JWKSourceResolver<C> {

    private static final Logger LOGGER = LoggerFactory.getLogger(URLJWKSourceResolver.class);
    private static final Duration CACHE_DURATION = Duration.ofMinutes(5);

    private final URL jwksUrl;
    private final ResourceRetriever resourceRetriever;

    static final ConcurrentHashMap<String, CachedJWKSource> cache = new ConcurrentHashMap<>();

    public URLJWKSourceResolver(TemplateEngine templateEngine, String url, ResourceRetriever resourceRetriever)
        throws MalformedURLException {
        this.jwksUrl = new URL(templateEngine.getValue(url, String.class));
        this.resourceRetriever = resourceRetriever;
    }

    @Override
    public CompletableFuture<JWKSource<C>> resolve() {
        CachedJWKSource cachedJWKSource = cache.get(jwksUrl.toString());
        if (cachedJWKSource != null && !isCacheExpired(cachedJWKSource)) {
            return CompletableFuture.completedFuture(cachedJWKSource.getJwkSource());
        }

        return resourceRetriever
            .retrieve(jwksUrl)
            .thenCompose(this::readJwkSourceFromResource)
            .exceptionally(ex -> {
                if (cachedJWKSource != null) {
                    LOGGER.warn("Failed to retreive JWKS from URL {}. Using old cached JWKS", jwksUrl, ex);
                    return cachedJWKSource.getJwkSource();
                }
                return null;
            });
    }

    boolean isCacheExpired(CachedJWKSource cachedJWKSource) {
        return Duration.between(cachedJWKSource.getCacheDateTime(), LocalDateTime.now()).compareTo(CACHE_DURATION) > 0;
    }

    private CompletableFuture<JWKSource<C>> readJwkSourceFromResource(Resource resource) {
        try {
            JWKSet parsedJWKSet = JWKSet.parse(resource.getContent());
            ImmutableJWKSet<C> immutableJWKSet = new ImmutableJWKSet<>(parsedJWKSet);
            cache.put(jwksUrl.toString(), new CachedJWKSource(immutableJWKSet));
            return CompletableFuture.completedFuture(immutableJWKSet);
        } catch (ParseException e) {
            return CompletableFuture.failedFuture(e);
        }
    }
}
