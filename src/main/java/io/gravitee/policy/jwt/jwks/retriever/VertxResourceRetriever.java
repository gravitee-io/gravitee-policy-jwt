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
package io.gravitee.policy.jwt.jwks.retriever;

import com.nimbusds.jose.util.Resource;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import java.net.URL;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class VertxResourceRetriever implements ResourceRetriever {

    private static final Logger LOGGER = LoggerFactory.getLogger(VertxResourceRetriever.class);
    private static final String HTTPS_SCHEME = "https";

    private final Vertx vertx;
    private final Environment environment;
    private final boolean useSystemProxy;

    public VertxResourceRetriever(final Vertx vertx, Environment environment, boolean useSystemProxy) {
        this.vertx = vertx;
        this.environment = environment;
        this.useSystemProxy = useSystemProxy;
    }

    @Override
    public CompletableFuture<Resource> retrieve(URL url) {
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(2000);

        if (useSystemProxy) {
            options.setProxyOptions(getSystemProxyOptions(url));
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

    private ProxyOptions getSystemProxyOptions(URL url) {
        StringBuilder errors = new StringBuilder();
        ProxyOptions proxyOptions = new ProxyOptions();

        // System proxy must be well configured. Check that this is the case.
        if (environment.containsProperty("system.proxy.host")) {
            proxyOptions.setHost(environment.getProperty("system.proxy.host"));
        } else {
            errors.append("'system.proxy.host' ");
        }

        try {
            proxyOptions.setPort(Integer.parseInt(Objects.requireNonNull(environment.getProperty("system.proxy.port"))));
        } catch (Exception e) {
            errors.append("'system.proxy.port' [").append(environment.getProperty("system.proxy.port")).append("] ");
        }

        try {
            proxyOptions.setType(ProxyType.valueOf(environment.getProperty("system.proxy.type")));
        } catch (Exception e) {
            errors.append("'system.proxy.type' [").append(environment.getProperty("system.proxy.type")).append("] ");
        }

        proxyOptions.setUsername(environment.getProperty("system.proxy.username"));
        proxyOptions.setPassword(environment.getProperty("system.proxy.password"));

        if (errors.length() == 0) {
            return proxyOptions;
        } else {
            LOGGER.warn(
                "JWTPlugin requires a system proxy to be defined to retrieve resource [{}] but some configurations are missing or not well defined: {}",
                url.toString(),
                errors
            );
            LOGGER.warn("Ignoring system proxy");
            return null;
        }
    }
}
