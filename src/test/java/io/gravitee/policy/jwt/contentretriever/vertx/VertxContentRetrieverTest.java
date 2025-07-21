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

import static com.github.tomakehurst.wiremock.client.WireMock.*;

import com.github.tomakehurst.wiremock.client.BasicCredentials;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.AuthConfiguration;
import io.gravitee.policy.jwt.configuration.SecurityType;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.vertx.rxjava3.core.Vertx;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;

@WireMockTest
class VertxContentRetrieverTest {

    public static final String SAMPLE_RESPONSE = """
            id1
            id2
            id3
            id4
            id5""";

    @Mock
    private Configuration configuration;

    @Test
    void should_fetch_content(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/ids")).willReturn(ok().withBody(SAMPLE_RESPONSE).withHeader("Content-Type", "text/plain")));

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            null
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/ids")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertValue(content -> content.content().equals(SAMPLE_RESPONSE))
            .assertValue(content -> content.contentType().equals("text/plain"));

        verify(getRequestedFor(urlPathEqualTo("/ids")));
    }

    @Test
    void should_fetch_jwks_json(WireMockRuntimeInfo wmRuntimeInfo) {
        String JWKS_JSON =
            """
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

        stubFor(
            get(urlPathEqualTo("/.well-known/jwks.json"))
                .willReturn(ok().withBody(JWKS_JSON).withHeader("Content-Type", "application/json"))
        );

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            null
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/.well-known/jwks.json")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertValue(content -> content.content().equals(JWKS_JSON))
            .assertValue(content -> content.contentType().equals("application/json"));

        verify(getRequestedFor(urlPathEqualTo("/.well-known/jwks.json")));
    }

    @ParameterizedTest
    @ValueSource(booleans = { true, false })
    void should_follow_redirects(boolean permanent, WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/old-ids")).willReturn(permanent ? permanentRedirect("/ids") : temporaryRedirect("/ids")));
        stubFor(get(urlPathEqualTo("/ids")).willReturn(ok().withBody(SAMPLE_RESPONSE)));

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().followRedirects(true).build(),
            null
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/old-ids")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertValue(content -> content.content().equals(SAMPLE_RESPONSE));

        verify(getRequestedFor(urlPathEqualTo("/old-ids")));
        verify(getRequestedFor(urlPathEqualTo("/ids")));
    }

    @Test
    void should_handle_error_status(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/ids")).willReturn(notFound()));

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            null
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/ids")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertError(throwable -> throwable.getMessage().contains("Invalid status code 404"));

        verify(getRequestedFor(urlPathEqualTo("/ids")));
    }

    @Test
    void should_handle_invalid_url() {
        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            null
        );

        contentRetriever
            .retrieve("invalid-url")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertError(throwable -> throwable instanceof java.net.MalformedURLException);
    }

    @Test
    void should_reject_very_large_response(WireMockRuntimeInfo wmRuntimeInfo) {
        // Create a response that exceeds MAX_RESPONSE_SIZE (5MB)
        byte[] largeResponse = new byte[6 * 1024 * 1024]; // 6MB
        stubFor(get(urlPathEqualTo("/large")).willReturn(ok().withBody(largeResponse)));

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            null
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/large")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertError(throwable ->
                throwable instanceof IllegalStateException &&
                throwable.getMessage().contains("Response size") &&
                throwable.getMessage().contains("exceeds maximum allowed size")
            );

        verify(getRequestedFor(urlPathEqualTo("/large")));
    }

    @Test
    void should_handle_basic_auth(WireMockRuntimeInfo wmRuntimeInfo) {
        stubFor(get(urlPathEqualTo("/ids")).withBasicAuth("testuser", "testpass").willReturn(ok().withBody(SAMPLE_RESPONSE)));

        AuthConfiguration authConfig = new AuthConfiguration();
        authConfig.setType(SecurityType.BASIC);
        AuthConfiguration.Basic basicAuth = new AuthConfiguration.Basic();
        basicAuth.setUsername("testuser");
        basicAuth.setPassword("testpass");
        authConfig.setBasic(basicAuth);

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            authConfig
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/ids")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertValue(content -> content.content().equals(SAMPLE_RESPONSE));

        verify(getRequestedFor(urlPathEqualTo("/ids")).withBasicAuth(new BasicCredentials("testuser", "testpass")));
    }

    @Test
    void should_handle_bearer_token(WireMockRuntimeInfo wmRuntimeInfo) {
        String token = "test-token";
        stubFor(
            get(urlPathEqualTo("/ids")).withHeader("Authorization", equalTo("Bearer " + token)).willReturn(ok().withBody(SAMPLE_RESPONSE))
        );

        AuthConfiguration authConfig = new AuthConfiguration();
        authConfig.setType(SecurityType.TOKEN);
        AuthConfiguration.Token tokenAuth = new AuthConfiguration.Token();
        tokenAuth.setValue(token);
        authConfig.setToken(tokenAuth);

        VertxContentRetriever contentRetriever = new VertxContentRetriever(
            Vertx.vertx(),
            configuration,
            RetrieveOptions.builder().build(),
            authConfig
        );

        contentRetriever
            .retrieve(wmRuntimeInfo.getHttpBaseUrl() + "/ids")
            .test()
            .awaitDone(10, TimeUnit.SECONDS)
            .assertValue(content -> content.content().equals(SAMPLE_RESPONSE));

        verify(getRequestedFor(urlPathEqualTo("/ids")).withHeader("Authorization", equalTo("Bearer " + token)));
    }
}
