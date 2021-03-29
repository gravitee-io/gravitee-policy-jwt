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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.gravitee.el.TemplateEngine;
import io.gravitee.policy.jwt.jwks.retriever.ResourceRetriever;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class URLJWKSourceResolver<C extends SecurityContext> implements JWKSourceResolver<C> {

    private final URL jwksUrl;
    private final ResourceRetriever resourceRetriever;

    private final static Cache<String, JWKSource> cache = CacheBuilder
            .newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build();

    public URLJWKSourceResolver(TemplateEngine templateEngine, String url, ResourceRetriever resourceRetriever) throws MalformedURLException {
        this.jwksUrl = new URL(templateEngine.getValue(url, String.class));
        this.resourceRetriever = resourceRetriever;
    }

    @Override
    public CompletableFuture<JWKSource<C>> resolve() {
        JWKSource<C> jwkSource = cache.getIfPresent(jwksUrl.toString());

        if (jwkSource == null) {
            return resourceRetriever
                    .retrieve(jwksUrl)
                    .thenCompose(resource -> {
                        try {
                            JWKSet parsedJWKSet = JWKSet.parse(resource.getContent());
                            ImmutableJWKSet<C> immutableJWKSet = new ImmutableJWKSet<>(parsedJWKSet);
                            cache.put(jwksUrl.toString(), immutableJWKSet);
                            return CompletableFuture.completedFuture(immutableJWKSet);
                        } catch (ParseException e) {
                            return CompletableFuture.completedFuture(null);
                        }
                    });
        }

        return CompletableFuture.completedFuture(jwkSource);
    }
}
