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

import com.nimbusds.jose.util.Resource;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.net.URL;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class VertxResourceRetriever implements ResourceRetriever {

    private static final Logger log = LoggerFactory.getLogger(VertxResourceRetriever.class);
    private static final String HTTPS_SCHEME = "https";

    private final Vertx vertx;
    private final Configuration configuration;
    private final boolean useSystemProxy;

    private final int connectTimeout;
    private final long requestTimeout;

    public VertxResourceRetriever(final Vertx vertx, Configuration configuration, RetrieveOptions options) {
        this.vertx = vertx;
        this.configuration = configuration;
        this.useSystemProxy = options.isUseSystemProxy();
        this.connectTimeout = options.getConnectTimeout();
        this.requestTimeout = options.getRequestTimeout();
    }

    public Single<Resource> retrieve(String url) {
        final URL finalURL;

        try {
            finalURL = new URL(url);
        } catch (Throwable throwable) {
            return Single.error(throwable);
        }

        HttpClient httpClient = buildHttpClient(finalURL);

        final RequestOptions requestOptions = new RequestOptions().setMethod(HttpMethod.GET).setAbsoluteURI(url).setTimeout(requestTimeout);

        return httpClient
            .rxRequest(requestOptions)
            .flatMap(HttpClientRequest::rxSend)
            .flatMap(response -> {
                if (response.statusCode() >= 200 && response.statusCode() <= 299) {
                    return response.rxBody().map(buffer -> new Resource(buffer.toString(), response.getHeader(HttpHeaders.CONTENT_TYPE)));
                } else {
                    return Single.error(new Exception("Status code from JWKS URL is not valid: " + response.statusCode()));
                }
            })
            .doFinally(httpClient::close);
    }

    private HttpClient buildHttpClient(URL url) {
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(connectTimeout);

        if (useSystemProxy) {
            try {
                options.setProxyOptions(VertxProxyOptionsUtils.buildProxyOptions(configuration));
            } catch (Exception e) {
                log.warn(
                    "JWTPlugin requires a system proxy to be defined to retrieve resource [{}] but some configurations are missing or not well defined: {}",
                    url.toString(),
                    e.getMessage()
                );
                log.warn("Ignoring system proxy");
            }
        }

        if (HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol())) {
            options.setSsl(true);
        }

        return vertx.createHttpClient(options);
    }
}
