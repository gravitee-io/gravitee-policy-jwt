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
import io.vertx.core.http.PoolOptions;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;

/**
 * Shares Vert.x HTTP clients between content retrievals. A client is bound to the Vert.x context that was current
 * when it was created, and a closed client stays referenced by that context. Creating (and closing) one client per
 * fetch therefore grows the heap on every fetch; clients are created once per distinct set of options and reused.
 */
@Slf4j
public final class SharedHttpClients {

    private static final String HTTPS_SCHEME = "https";

    /**
     * Max HTTP/1 connections per host. The default of 5 is too low once every plan using the same identity provider
     * shares one client: concurrent key refreshes would wait for a connection and hit the request timeout.
     */
    private static final int HTTP1_MAX_POOL_SIZE = 50;

    // Bounded in practice: one Vert.x instance and a handful of distinct option sets.
    private static final Map<Key, HttpClient> CLIENTS = new ConcurrentHashMap<>();

    private SharedHttpClients() {}

    public static HttpClient get(Vertx vertx, Configuration configuration, boolean useSystemProxy, int connectTimeout, URL url) {
        boolean ssl = HTTPS_SCHEME.equalsIgnoreCase(url.getProtocol());
        return CLIENTS.computeIfAbsent(new Key(vertx, configuration, useSystemProxy, connectTimeout, ssl), key -> create(key, url));
    }

    /**
     * A client is closed together with the Vert.x context that created it. Drop it from the registry so that the next
     * call creates a new one instead of handing out a closed client forever.
     */
    public static void evict(HttpClient client) {
        CLIENTS.values().removeIf(cached -> cached == client);
    }

    public static boolean isClientClosed(Throwable throwable) {
        return throwable instanceof IllegalStateException && String.valueOf(throwable.getMessage()).toLowerCase().contains("closed");
    }

    private static HttpClient create(Key key, URL url) {
        HttpClientOptions options = new HttpClientOptions().setConnectTimeout(key.connectTimeout());

        if (key.useSystemProxy()) {
            try {
                options.setProxyOptions(VertxProxyOptionsUtils.buildProxyOptions(key.configuration()));
            } catch (Exception e) {
                log.warn(
                    "JWTPlugin requires a system proxy to be defined to retrieve resource [{}] but some configurations are missing or not well defined: {}",
                    url.toString(),
                    e.getMessage()
                );
                log.warn("Ignoring system proxy");
            }
        }

        if (key.ssl()) {
            options.setSsl(true).setTrustAll(true);
        }

        return key.vertx().createHttpClient(options, new PoolOptions().setHttp1MaxSize(HTTP1_MAX_POOL_SIZE));
    }

    private record Key(Vertx vertx, Configuration configuration, boolean useSystemProxy, int connectTimeout, boolean ssl) {}
}
