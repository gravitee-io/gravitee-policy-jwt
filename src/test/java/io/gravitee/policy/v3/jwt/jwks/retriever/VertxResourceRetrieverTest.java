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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.util.Resource;
import io.gravitee.node.api.configuration.Configuration;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.PoolOptions;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@WireMockTest
class VertxResourceRetrieverTest {

    public static final String JWKS_JSON = """
          {
            "keys" : [ {
              "kty" : "RSA",
              "use" : "sig",
              "alg" : "RS256",
              "kid" : "default",
              "x5c" : [ "MIICvzCCA..." ],
              "x5t#S256" : "_0VtTmrWiO...",
              "e" : "AQAB",
              "n" : "g4ygRnkRBwPHmHNP8..."
            } ]
          }
        """;

    @Mock
    private Configuration configuration;

    @Test
    @SneakyThrows
    void should_fetch_resource(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/.well-known/jwks.json")).willReturn(okJson(JWKS_JSON)));

        VertxResourceRetriever vertxResourceRetriever = new VertxResourceRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build()
        );

        Resource resource = vertxResourceRetriever
            .retrieve(new URL(wmRuntimeInfo.getHttpBaseUrl() + "/.well-known/jwks.json"))
            .get(10, TimeUnit.SECONDS);
        assertThat(resource).isNotNull();
        assertThat(resource.getContent()).isEqualTo(JWKS_JSON);

        verify(getRequestedFor(urlPathEqualTo("/.well-known/jwks.json")));
    }

    @SneakyThrows
    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void should_follow_http_temporary_redirects(boolean permanent, WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(
            get(urlPathEqualTo("/.well-known/old-jwks.json")).willReturn(
                permanent ? permanentRedirect("/.well-known/jwks.json") : temporaryRedirect("/.well-known/jwks.json")
            )
        );
        stubFor(get(urlPathEqualTo("/.well-known/jwks.json")).willReturn(okJson(JWKS_JSON)));

        VertxResourceRetriever vertxResourceRetriever = new VertxResourceRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().followRedirects(true).build()
        );

        Resource resource = vertxResourceRetriever
            .retrieve(new URL(wmRuntimeInfo.getHttpBaseUrl() + "/.well-known/old-jwks.json"))
            .get(10, TimeUnit.SECONDS);
        assertThat(resource).isNotNull();
        assertThat(resource.getContent()).isEqualTo(JWKS_JSON);

        verify(getRequestedFor(urlPathEqualTo("/.well-known/old-jwks.json")));
        verify(getRequestedFor(urlPathEqualTo("/.well-known/jwks.json")));
    }

    @Test
    @SneakyThrows
    void should_reuse_one_http_client_across_failed_fetches() {
        Vertx vertx = Mockito.spy(Vertx.vertx());
        VertxResourceRetriever vertxResourceRetriever = new VertxResourceRetriever(
            vertx,
            configuration,
            RetrieveOptions.builder().connectTimeout(500).requestTimeout(500L).build()
        );

        for (int i = 0; i < 5; i++) {
            assertThat(vertxResourceRetriever.retrieve(new URL("http://127.0.0.1:1/jwks.json"))).failsWithin(10, TimeUnit.SECONDS);
        }

        Mockito.verify(vertx, Mockito.times(1)).createHttpClient(any(HttpClientOptions.class), any(PoolOptions.class));
    }

    @Test
    @SneakyThrows
    void should_fetch_again_after_non_success_statuses(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/.well-known/jwks.json")).willReturn(serverError()));
        VertxResourceRetriever vertxResourceRetriever = new VertxResourceRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build()
        );
        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/.well-known/jwks.json");

        for (int i = 0; i < 20; i++) {
            assertThat(vertxResourceRetriever.retrieve(url)).failsWithin(10, TimeUnit.SECONDS);
        }
        stubFor(get(urlPathEqualTo("/.well-known/jwks.json")).willReturn(okJson(JWKS_JSON)));

        assertThat(vertxResourceRetriever.retrieve(url).get(10, TimeUnit.SECONDS).getContent()).isEqualTo(JWKS_JSON);
    }

    @Test
    @SneakyThrows
    void should_replace_the_shared_client_when_the_verticle_that_created_it_is_undeployed(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/.well-known/jwks.json")).willReturn(okJson(JWKS_JSON)));
        Vertx vertx = Vertx.vertx();
        VertxResourceRetriever vertxResourceRetriever = new VertxResourceRetriever(vertx, configuration, RetrieveOptions.builder().build());
        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/.well-known/jwks.json");

        String deploymentId = vertx
            .deployVerticle(
                new AbstractVerticle() {
                    @Override
                    public void start(Promise<Void> startPromise) {
                        vertxResourceRetriever
                            .retrieve(url)
                            .whenComplete((resource, error) -> {
                                if (error != null) {
                                    startPromise.fail(error);
                                } else {
                                    startPromise.complete();
                                }
                            });
                    }
                }
            )
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
        vertx.undeploy(deploymentId).toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);

        assertThat(vertxResourceRetriever.retrieve(url).get(10, TimeUnit.SECONDS).getContent()).isEqualTo(JWKS_JSON);
    }
}
