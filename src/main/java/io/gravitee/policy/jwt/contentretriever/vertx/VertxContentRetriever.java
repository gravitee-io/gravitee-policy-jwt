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
package io.gravitee.policy.jwt.contentretriever.vertx;

import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.AuthConfiguration;
import io.gravitee.policy.jwt.configuration.SecurityType;
import io.gravitee.policy.jwt.contentretriever.Content;
import io.gravitee.policy.jwt.contentretriever.ContentRetriever;
import io.gravitee.policy.jwt.contentretriever.vertx.authentication.AuthenticationHandler;
import io.gravitee.policy.jwt.contentretriever.vertx.authentication.BasicAuthenticationHandler;
import io.gravitee.policy.jwt.contentretriever.vertx.authentication.BearerTokenAuthenticationHandler;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.net.URL;
import lombok.CustomLog;

@CustomLog
public class VertxContentRetriever implements ContentRetriever {

    private static final int MAX_RESPONSE_SIZE = 5_242_880; // 5MB

    private final Vertx vertx;
    private final Configuration configuration;
    private final boolean useSystemProxy;

    private final int connectTimeout;
    private final long requestTimeout;
    private final boolean followRedirects;
    private final AuthenticationHandler authHandler;

    public VertxContentRetriever(
        final Vertx vertx,
        Configuration configuration,
        RetrieveOptions options,
        AuthConfiguration authConfiguration
    ) {
        this.vertx = vertx;
        this.configuration = configuration;
        this.useSystemProxy = options.isUseSystemProxy();
        this.connectTimeout = options.getConnectTimeout();
        this.requestTimeout = options.getRequestTimeout();
        this.followRedirects = options.isFollowRedirects();
        this.authHandler = createAuthHandler(authConfiguration);
    }

    public Single<Content> retrieve(String url) {
        final URL finalURL;

        try {
            finalURL = new URL(url);
        } catch (Throwable throwable) {
            return Single.error(throwable);
        }

        return retrieve(finalURL, true);
    }

    private Single<Content> retrieve(URL finalURL, boolean retryOnClosedClient) {
        io.vertx.core.http.HttpClient delegate = SharedHttpClients.get(
            vertx.getDelegate(),
            configuration,
            useSystemProxy,
            connectTimeout,
            finalURL
        );
        HttpClient httpClient = HttpClient.newInstance(delegate);
        final RequestOptions requestOptions = buildRequestOptions(finalURL);

        return httpClient
            .rxRequest(requestOptions)
            .flatMap(HttpClientRequest::rxSend)
            .flatMap(response -> {
                if (response.statusCode() >= 200 && response.statusCode() <= 299) {
                    return response
                        .rxBody()
                        .map(buffer -> {
                            if (buffer.length() > MAX_RESPONSE_SIZE) {
                                throw new IllegalStateException(
                                    String.format(
                                        "Response size %d bytes exceeds maximum allowed size of %d bytes",
                                        buffer.length(),
                                        MAX_RESPONSE_SIZE
                                    )
                                );
                            }
                            return new Content(buffer.toString(), response.getHeader(HttpHeaders.CONTENT_TYPE));
                        });
                } else {
                    // Discard the body (without buffering it) so the connection goes back to the shared pool.
                    return response
                        .rxEnd()
                        .andThen(
                            Single.<Content>error(
                                new Exception(String.format("Invalid status code %d received from %s", response.statusCode(), finalURL))
                            )
                        );
                }
            })
            .onErrorResumeNext(throwable -> {
                if (retryOnClosedClient && SharedHttpClients.isClientClosed(throwable)) {
                    SharedHttpClients.evict(delegate);
                    return retrieve(finalURL, false);
                }
                return Single.error(throwable);
            });
    }

    private RequestOptions buildRequestOptions(URL finalURL) {
        RequestOptions options = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(finalURL)
            .setTimeout(requestTimeout)
            .setFollowRedirects(followRedirects);

        if (authHandler != null) {
            MultiMap authHeaders = authHandler.getAuthenticationHeaders();
            authHeaders.forEach(header -> options.putHeader(header.getKey(), header.getValue()));
        }

        return options;
    }

    private AuthenticationHandler createAuthHandler(AuthConfiguration authConfig) {
        if (authConfig == null || authConfig.getType() == SecurityType.NONE) {
            return null;
        }

        try {
            return switch (authConfig.getType()) {
                case BASIC -> new BasicAuthenticationHandler(authConfig.getBasic().getUsername(), authConfig.getBasic().getPassword());
                case TOKEN -> new BearerTokenAuthenticationHandler(authConfig.getToken().getValue());
                default -> {
                    log.warn("Unsupported authentication type: {}", authConfig.getType());
                    log.warn("Ignoring authentication configuration");
                    yield null;
                }
            };
        } catch (IllegalArgumentException e) {
            log.warn("Invalid {} auth configuration: {}", authConfig.getType().toString().toLowerCase(), e.getMessage());
            log.warn("Ignoring authentication configuration");
            return null;
        }
    }
}
