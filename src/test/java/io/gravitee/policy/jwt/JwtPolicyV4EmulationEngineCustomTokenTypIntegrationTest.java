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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gravitee.policy.jwt.alg.Signature.HMAC_HS256;
import static io.gravitee.policy.v3.jwt.resolver.KeyResolver.GIVEN_KEY;
import static io.vertx.core.http.HttpMethod.GET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
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
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientResponse;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/jwt.json")
public class JwtPolicyV4EmulationEngineCustomTokenTypIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

    private static final String CLIENT_ID = "my-test-client-id";
    private static final String JWT_SECRET;
    public static final String API_ID = "my-api";
    public static final String PLAN_ID = "plan-id";

    static {
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);
        JWT_SECRET = new String(sharedSecret);
    }

    /**
     * Override api plans to have a published JWT one.
     * @param api is the api to apply this function code
     */
    @Override
    public void configureApi(Api api) {
        Plan jwtPlan = new Plan();
        jwtPlan.setId(PLAN_ID);
        jwtPlan.setApi(api.getId());
        jwtPlan.setSecurity("JWT");
        jwtPlan.setStatus("PUBLISHED");

        JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
        configuration.setSignature(HMAC_HS256);
        configuration.setResolverParameter(JWT_SECRET);
        configuration.setPublicKeyResolver(GIVEN_KEY);
        JWTPolicyConfiguration.TokenTypValidation tokenTypValidation = new JWTPolicyConfiguration.TokenTypValidation();
        tokenTypValidation.setEnabled(true);
        tokenTypValidation.setIgnoreCase(false);
        tokenTypValidation.setExpectedValues(Collections.singletonList("token/at"));
        configuration.setTokenTypValidation(tokenTypValidation);
        try {
            jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to set JWT policy configuration", e);
        }

        api.setPlans(Collections.singletonList(jwtPlan));
    }

    @Test
    @DisplayName("Should access API with correct Authorization header and a valid subscription")
    void shouldAccessApiWithValidTokenAndSubscription(HttpClient httpClient) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken("token/at");

        // subscription found is valid
        whenSearchingSubscription().thenReturn(Optional.of(fakeSubscriptionFromCache()));

        httpClient
            .rxRequest(GET, "/test")
            .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).rxSend())
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 Unauthorized when Authorization header type is unexpected")
    void shouldReceive401UnauthorizedWhenAuthorizationHeaderTypeIsUnexpected(HttpClient httpClient) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken("token/AT");

        // subscription found is valid
        whenSearchingSubscription().thenReturn(Optional.of(fakeSubscriptionFromCache()));

        Single<HttpClientResponse> httpClientResponseSingle = httpClient
            .rxRequest(GET, "/test")
            .flatMap(request -> request.putHeader("Authorization", "Basic " + jwtToken).rxSend());

        assert401unauthorized(httpClientResponseSingle);
    }

    /**
     * Generate the Subscription object that would be returned by the SubscriptionService
     * @return the Subscription object
     */
    private Subscription fakeSubscriptionFromCache() {
        final Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan(PLAN_ID);
        return subscription;
    }

    private String getJsonWebToken(String type) throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
            .claim("client_id", CLIENT_ID)
            .expirationTime(Date.from(Instant.now().plusSeconds(5000)))
            .build();
        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(new JWSHeader(HMAC_HS256.getAlg())).type(new JOSEObjectType(type)).build(),
            jwtClaimsSet
        );
        signedJWT.sign(new MACSigner(JWT_SECRET));
        return signedJWT.serialize();
    }

    private void assert401unauthorized(Single<HttpClientResponse> httpClientResponse) throws InterruptedException {
        httpClientResponse
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertUnauthorizedResponseBody(body.toString());
                return true;
            })
            .assertNoErrors();
        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription() {
        return when(
            getBean(SubscriptionService.class).getByApiAndSecurityToken(
                eq(JwtPolicyV4EmulationEngineCustomTokenTypIntegrationTest.API_ID),
                securityTokenMatcher(),
                eq(JwtPolicyV4EmulationEngineCustomTokenTypIntegrationTest.PLAN_ID)
            )
        );
    }

    protected void assertUnauthorizedResponseBody(String responseBody) {
        assertThat(responseBody).isEqualTo("Unauthorized");
    }

    private SecurityToken securityTokenMatcher() {
        return argThat(
            securityToken ->
                securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) &&
                securityToken.getTokenValue().equals(JwtPolicyV4EmulationEngineCustomTokenTypIntegrationTest.CLIENT_ID)
        );
    }
}
