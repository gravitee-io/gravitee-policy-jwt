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
import io.gravitee.policy.jwt.vertx.VertxCompletableFuture;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.*;

import java.net.URL;
import java.util.concurrent.CompletableFuture;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class VertxResourceRetriever implements ResourceRetriever {

    private static final String HTTPS_SCHEME = "https";

    private final Vertx vertx;

    public VertxResourceRetriever(final Vertx vertx) {
        this.vertx = vertx;
    }

    @Override
    public CompletableFuture<Resource> retrieve(URL url) {
        HttpClientOptions options = new HttpClientOptions()
                .setConnectTimeout(2000);

        if (HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol())) {
            options.setSsl(true).setTrustAll(true);
        }

        Future<Resource> future = Future.future();
        HttpClient httpClient = vertx.createHttpClient(options);
        HttpClientRequest httpRequest = httpClient
                .requestAbs(HttpMethod.GET, url.toString())
                .handler(new Handler<HttpClientResponse>() {
                    @Override
                    public void handle(HttpClientResponse httpResponse) {
                        if (httpResponse.statusCode() >= 200 && httpResponse.statusCode() <= 299) {
                            httpResponse
                                    .bodyHandler(new Handler<Buffer>() {
                                        @Override
                                        public void handle(Buffer body) {
                                            future.complete(
                                                    new Resource(body.toString(),
                                                    httpResponse.getHeader(io.gravitee.common.http.HttpHeaders.CONTENT_TYPE)));

                                            httpClient.close();
                                        }
                                    });
                        } else {
                            future.fail("Status code from JWKS URL is not valid: " + httpResponse.statusCode());
                            httpClient.close();
                        }
                    }
                }).exceptionHandler(throwable -> {
                    // Finally exit chain
                    future.fail(throwable);
                    httpClient.close();
                }).setTimeout(2000);

        httpRequest.end();

        return VertxCompletableFuture.from(vertx, future);
    }
}
