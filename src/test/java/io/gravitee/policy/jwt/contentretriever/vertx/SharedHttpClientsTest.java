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

import static org.assertj.core.api.Assertions.assertThat;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import java.net.URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SharedHttpClientsTest {

    private Vertx vertx;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    @Test
    void should_return_the_same_client_for_identical_options() throws Exception {
        URL url = new URL("https://idp.example.com/jwks.json");

        assertThat(SharedHttpClients.get(vertx, null, false, 1000, url)).isSameAs(SharedHttpClients.get(vertx, null, false, 1000, url));
    }

    @Test
    void should_return_the_same_client_for_two_urls_with_the_same_scheme() throws Exception {
        assertThat(SharedHttpClients.get(vertx, null, false, 1000, new URL("https://a.example.com/jwks.json"))).isSameAs(
            SharedHttpClients.get(vertx, null, false, 1000, new URL("HTTPS://b.example.com/other.json"))
        );
    }

    @Test
    void should_return_distinct_clients_when_ssl_timeout_or_proxy_differ() throws Exception {
        URL http = new URL("http://idp.example.com/jwks.json");
        URL https = new URL("https://idp.example.com/jwks.json");

        HttpClient reference = SharedHttpClients.get(vertx, null, false, 1000, http);

        assertThat(SharedHttpClients.get(vertx, null, false, 1000, https)).isNotSameAs(reference);
        assertThat(SharedHttpClients.get(vertx, null, false, 2000, http)).isNotSameAs(reference);
        assertThat(SharedHttpClients.get(vertx, null, true, 1000, http)).isNotSameAs(reference);
    }

    @Test
    void should_create_a_new_client_after_eviction() throws Exception {
        URL url = new URL("http://idp.example.com/jwks.json");
        HttpClient first = SharedHttpClients.get(vertx, null, false, 1000, url);

        SharedHttpClients.evict(first);

        assertThat(SharedHttpClients.get(vertx, null, false, 1000, url)).isNotSameAs(first);
    }
}
