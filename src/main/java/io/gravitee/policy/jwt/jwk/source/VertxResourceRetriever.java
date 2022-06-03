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
package io.gravitee.policy.jwt.jwk.source;

import com.nimbusds.jose.util.Resource;
import io.gravitee.common.util.VertxProxyOptionsUtils;
import io.gravitee.node.api.configuration.Configuration;
import io.reactivex.Single;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.reactivex.core.Vertx;
import io.vertx.reactivex.core.http.HttpClient;
import io.vertx.reactivex.core.http.HttpClientRequest;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class VertxResourceRetriever implements ResourceRetriever {

    private static final Logger log = LoggerFactory.getLogger(VertxResourceRetriever.class);
    private static final String HTTPS_SCHEME = "https";
    protected static final int DEFAULT_TIMEOUT = 2000;

    private final Vertx vertx;
    private final Configuration configuration;
    private final boolean useSystemProxy;

    public VertxResourceRetriever(final Vertx vertx, Configuration configuration, boolean useSystemProxy) {
        this.vertx = vertx;
        this.configuration = configuration;
        this.useSystemProxy = useSystemProxy;
    }

    public Single<Resource> retrieve(String url) {
        final URL finalURL;

        try {
            finalURL = new URL(url);
        } catch (Throwable throwable) {
            return Single.error(throwable);
        }

        HttpClient httpClient = buildHttpClient(finalURL);

        final RequestOptions requestOptions = new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(url)
            .setTimeout(DEFAULT_TIMEOUT);

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
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(DEFAULT_TIMEOUT);

        if (useSystemProxy) {
            try {
                VertxProxyOptionsUtils.setSystemProxy(options, configuration);
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
