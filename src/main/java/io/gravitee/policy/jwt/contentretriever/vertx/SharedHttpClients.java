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
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.CustomLog;

/**
 * Shares Vert.x HTTP clients between content retrievals. A client is bound to the Vert.x context that was current
 * when it was created, and a closed client stays referenced by that context. Creating (and closing) one client per
 * fetch therefore grows the heap on every fetch; clients are created once per distinct set of options and reused.
 */
@CustomLog
public final class SharedHttpClients {

    private static final String HTTPS_SCHEME = "https";

    private static final Map<Key, HttpClient> CLIENTS = new ConcurrentHashMap<>();

    private SharedHttpClients() {}

    public static HttpClient get(Vertx vertx, Configuration configuration, boolean useSystemProxy, int connectTimeout, URL url) {
        boolean ssl = HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol());
        return CLIENTS.computeIfAbsent(new Key(vertx, configuration, useSystemProxy, connectTimeout, ssl), key ->
            create(vertx, configuration, useSystemProxy, connectTimeout, ssl, url)
        );
    }

    private static HttpClient create(
        Vertx vertx,
        Configuration configuration,
        boolean useSystemProxy,
        int connectTimeout,
        boolean ssl,
        URL url
    ) {
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

        if (ssl) {
            options.setSsl(true).setTrustAll(true);
        }

        return vertx.createHttpClient(options);
    }

    private record Key(Vertx vertx, Configuration configuration, boolean useSystemProxy, int connectTimeout, boolean ssl) {}
}
