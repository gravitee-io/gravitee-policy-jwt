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
package io.gravitee.policy.v3.jwt.jwks.retriever;

import com.nimbusds.jose.util.Resource;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.contentretriever.vertx.SharedHttpClients;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import lombok.extern.slf4j.Slf4j;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class VertxResourceRetriever implements ResourceRetriever {

    private final Vertx vertx;
    private final Configuration configuration;
    private final boolean useSystemProxy;

    private final int connectTimeout;
    private final long requestTimeout;
    private final boolean followRedirects;

    public VertxResourceRetriever(final Vertx vertx, Configuration configuration, RetrieveOptions options) {
        this.vertx = vertx;
        this.configuration = configuration;
        this.useSystemProxy = options.isUseSystemProxy();
        this.connectTimeout = options.getConnectTimeout();
        this.requestTimeout = options.getRequestTimeout();
        this.followRedirects = options.isFollowRedirects();
    }

    @Override
    public CompletableFuture<Resource> retrieve(URL url) {
        return retrieve(url, true);
    }

    private CompletableFuture<Resource> retrieve(URL url, boolean retryOnClosedClient) {
        HttpClient httpClient = SharedHttpClients.get(vertx, configuration, useSystemProxy, connectTimeout, url);

        Promise<Resource> promise = Promise.promise();

        final RequestOptions requestOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(url.toString())
            .setTimeout(requestTimeout)
            .setFollowRedirects(followRedirects);

        try {
            httpClient
                .request(requestOptions)
                .compose(HttpClientRequest::send)
                .onFailure(promise::fail)
                .onSuccess(httpResponse -> handleResponse(promise, httpResponse));
        } catch (IllegalStateException e) {
            // Thrown synchronously when the client has been closed.
            promise.tryFail(e);
        }

        return promise
            .future()
            .recover(throwable -> {
                if (retryOnClosedClient && SharedHttpClients.isClientClosed(throwable)) {
                    SharedHttpClients.evict(httpClient);
                    return Future.fromCompletionStage(retrieve(url, false));
                }
                return Future.failedFuture(throwable);
            })
            .toCompletionStage()
            .toCompletableFuture();
    }

    private void handleResponse(Promise<Resource> promise, HttpClientResponse httpResponse) {
        if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() <= 299) {
            httpResponse.bodyHandler(body ->
                promise.complete(new Resource(body.toString(), httpResponse.getHeader(io.gravitee.common.http.HttpHeaders.CONTENT_TYPE)))
            );
        } else {
            httpResponse.end();
            promise.fail("Status code from JWKS URL is not valid: " + httpResponse.statusCode());
        }
    }
}
