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
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class VertxResourceRetriever implements ResourceRetriever {

    private static final Logger LOGGER = LoggerFactory.getLogger(VertxResourceRetriever.class);
    private static final String HTTPS_SCHEME = "https";

    private final Vertx vertx;
    private final Configuration configuration;
    private final boolean useSystemProxy;

    public VertxResourceRetriever(final Vertx vertx, Configuration configuration, boolean useSystemProxy) {
        this.vertx = vertx;
        this.configuration = configuration;
        this.useSystemProxy = useSystemProxy;
    }

    @Override
    public CompletableFuture<Resource> retrieve(URL url) {
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(2000);

        if (useSystemProxy) {
            try {
                options.setProxyOptions(VertxProxyOptionsUtils.buildProxyOptions(configuration));
            } catch (Exception e) {
                LOGGER.warn(
                    "JWTPlugin requires a system proxy to be defined to retrieve resource [{}] but some configurations are missing or not well defined: {}",
                    url.toString(),
                    e.getMessage()
                );
                LOGGER.warn("Ignoring system proxy");
            }
        }

        if (HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol())) {
            options.setSsl(true).setTrustAll(true);
        }

        HttpClient httpClient = vertx.createHttpClient(options);

        Promise<Resource> promise = Promise.promise();

        final RequestOptions requestOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(url.toString())
            .setTimeout(2000L);

        final Future<HttpClientRequest> futureRequest = httpClient.request(requestOptions);

        futureRequest
            .onFailure(throwable -> handleFailure(httpClient, promise, throwable))
            .onSuccess(httpRequest ->
                httpRequest
                    .send()
                    .onFailure(throwable -> handleFailure(httpClient, promise, throwable))
                    .onSuccess(httpResponse -> handleSuccess(httpClient, promise, httpResponse))
            );

        return promise.future().toCompletionStage().toCompletableFuture();
    }

    private void handleSuccess(HttpClient httpClient, Promise<Resource> promise, HttpClientResponse httpResponse) {
        if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() <= 299) {
            httpResponse.bodyHandler(body -> {
                promise.complete(new Resource(body.toString(), httpResponse.getHeader(io.gravitee.common.http.HttpHeaders.CONTENT_TYPE)));
                httpClient.close();
            });
        } else {
            httpResponse.end(event -> httpClient.close());
            promise.fail("Status code from JWKS URL is not valid: " + httpResponse.statusCode());
        }
    }

    private void handleFailure(HttpClient httpClient, Promise<Resource> promise, Throwable throwable) {
        // Finally exit chain
        httpClient.close();
        promise.fail(throwable);
    }
}
