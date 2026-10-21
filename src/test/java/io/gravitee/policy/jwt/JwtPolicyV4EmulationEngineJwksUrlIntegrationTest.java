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
package io.gravitee.policy.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.serverError;
import static io.gravitee.policy.jwt.alg.Signature.RSA_RS256;
import static io.gravitee.policy.v3.jwt.resolver.KeyResolver.JWKS_URL;
import static io.vertx.core.http.HttpMethod.GET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Runs the JWKS_URL key resolver through the gateway, so the shared HTTP client is used from the real event loops.
 */
@GatewayTest
@DeployApi("/apis/jwt.json")
class JwtPolicyV4EmulationEngineJwksUrlIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

    private static final String CLIENT_ID = "my-test-client-id";
    private static final String API_ID = "my-api";
    private static final String PLAN_ID = "plan-id";
    private static final RSAKey RSA_KEY = generateKey();

    @Override
    public void configureApi(Api api) {
        Plan jwtPlan = new Plan();
        jwtPlan.setId(PLAN_ID);
        jwtPlan.setApi(api.getId());
        jwtPlan.setSecurity("JWT");
        jwtPlan.setStatus("PUBLISHED");

        JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
        configuration.setSignature(RSA_RS256);
        configuration.setPublicKeyResolver(JWKS_URL);
        configuration.setResolverParameter("http://localhost:" + wiremock.port() + "/jwks.json");
        try {
            jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to set JWT policy configuration", e);
        }

        api.setPlans(Collections.singletonList(jwtPlan));
    }

    @Test
    void should_not_authorize_while_the_jwks_url_fails_then_accept_once_it_recovers(HttpClient httpClient) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));
        whenSearchingSubscription().thenReturn(Optional.of(subscription()));
        String jwtToken = jsonWebToken();

        wiremock.stubFor(get("/jwks.json").willReturn(serverError()));
        for (int i = 0; i < 3; i++) {
            assertThat(statusOf(httpClient, jwtToken)).isGreaterThanOrEqualTo(400);
        }

        wiremock.stubFor(get("/jwks.json").willReturn(okJson(new JWKSet(RSA_KEY.toPublicJWK()).toString())));
        assertThat(statusOf(httpClient, jwtToken)).isEqualTo(200);
    }

    private int statusOf(HttpClient httpClient, String jwtToken) {
        return httpClient
            .rxRequest(GET, "/test")
            .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).rxSend())
            .map(response -> response.statusCode())
            .blockingGet();
    }

    private org.mockito.stubbing.OngoingStubbing<Optional<Subscription>> whenSearchingSubscription() {
        return when(
            getBean(SubscriptionService.class).getByApiAndSecurityToken(
                eq(API_ID),
                argThat(
                    securityToken ->
                        securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) &&
                        securityToken.getTokenValue().equals(CLIENT_ID)
                ),
                eq(PLAN_ID)
            )
        );
    }

    private static Subscription subscription() {
        Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan(PLAN_ID);
        return subscription;
    }

    private static String jsonWebToken() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("client_id", CLIENT_ID)
            .expirationTime(Date.from(Instant.now().plusSeconds(5000)))
            .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(RSA_RS256.getAlg()).keyID(RSA_KEY.getKeyID()).build(), claims);
        signedJWT.sign(new RSASSASigner(RSA_KEY));
        return signedJWT.serialize();
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-key").generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
