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

import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.gravitee.policy.jwt.contentretriever.vertx.VertxContentRetriever;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.reactivex.rxjava3.schedulers.Schedulers;
import io.vertx.rxjava3.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class RevocationCheckFactory {

    private static final Logger log = LoggerFactory.getLogger(RevocationCheckFactory.class);

    public static RevocationCheck create(JWTPolicyConfiguration.RevocationCheck configuration, BaseExecutionContext ctx) {
        if (!configuration.isValid()) {
            return new RevocationCheck(configuration, null);
        }

        JWTPolicyConfiguration.RevocationCheck normalizedConfig = configuration.normalized();
        ContentRetriever contentRetriever = createContentRetriever(normalizedConfig, ctx);
        RevocationCache revocationCache = createRevocationCache(normalizedConfig, contentRetriever);

        return new RevocationCheck(normalizedConfig, revocationCache);
    }

    private static ContentRetriever createContentRetriever(JWTPolicyConfiguration.RevocationCheck configuration, BaseExecutionContext ctx) {
        return new VertxContentRetriever(
            ctx.getComponent(Vertx.class),
            ctx.getComponent(Configuration.class),
            RetrieveOptions
                .builder()
                .connectTimeout(configuration.getConnectTimeout())
                .requestTimeout(configuration.getRequestTimeout())
                .useSystemProxy(configuration.isUseSystemProxy())
                .followRedirects(configuration.isFollowRedirects())
                .build(),
            configuration.getAuth()
        );
    }

    private static RevocationCache createRevocationCache(
        JWTPolicyConfiguration.RevocationCheck configuration,
        ContentRetriever contentRetriever
    ) {
        RevocationCache cache = new RevocationCache(
            configuration.getRevocationListUrl(),
            configuration.getRefreshInterval(),
            contentRetriever
        );

        cache
            .initialize()
            .subscribeOn(Schedulers.io())
            .subscribe(
                () -> log.info("Revocation cache initialized successfully"),
                error -> log.error("Failed to initialize revocation cache, revocation check is disabled", error)
            );

        return cache;
    }
}
