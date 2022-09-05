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
package io.gravitee.policy.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gravitee.policy.jwt.alg.Signature.HMAC_HS256;
import static io.gravitee.policy.v3.jwt.resolver.KeyResolver.GIVEN_KEY;
import static java.time.temporal.ChronoUnit.HOURS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.ExecutionMode;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.service.ApiKey;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.gateway.jupiter.api.policy.SecurityToken;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.reactivex.observers.TestObserver;
import io.vertx.reactivex.core.buffer.Buffer;
import io.vertx.reactivex.ext.web.client.HttpResponse;
import io.vertx.reactivex.ext.web.client.WebClient;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/jwt.json")
public class JwtPolicyIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

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

    @Override
    protected void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
        super.configureGateway(gatewayConfigurationBuilder);
        gatewayConfigurationBuilder.set("api.jupiterMode.enabled", "true");
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
        try {
            jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to set JWT policy configuration", e);
        }

        api.setPlans(Collections.singletonList(jwtPlan));
        api.setExecutionMode(ExecutionMode.JUPITER);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling without any Authorization Header")
    void shouldGet401_ifNoToken(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").rxSend().test();

        assert401unauthorized(obs);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with a wrong Authorization Header")
    void shouldGet401_ifWrongToken(WebClient client) {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        final TestObserver<HttpResponse<Buffer>> obs = client
            .get("/test")
            .putHeader("Authorization", "Bearer this_is_wrong")
            .rxSend()
            .test();

        assert401unauthorized(obs);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an expired token")
    void shouldGet401_ifExpiredToken(WebClient client) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken(-50);

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("Authorization", "Bearer " + jwtToken).rxSend().test();

        assert401unauthorized(obs);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an valid token, but no subscription")
    void shouldGet401_ifNoSubscription(WebClient client) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken(5000);

        // no subscription found
        whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.empty());

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("Authorization", "Bearer " + jwtToken).rxSend().test();

        assert401unauthorized(obs);
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling with an valid token, but subscription is expired")
    void shouldGet401_ifSubscriptionExpired(WebClient client) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken(5000);

        // subscription found is expired
        whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(true)));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("Authorization", "Bearer " + jwtToken).rxSend().test();

        assert401unauthorized(obs);
    }

    @Test
    @DisplayName("Should access API with correct Authorization header and a valid subscription")
    void shouldAccessApiWithValidTokenAndSubscription(WebClient client) throws Exception {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        String jwtToken = getJsonWebToken(5000);

        // subscription found is valid
        whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

        final TestObserver<HttpResponse<Buffer>> obs = client.get("/test").putHeader("Authorization", "Bearer " + jwtToken).rxSend().test();

        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.bodyAsString()).isEqualTo("response from backend");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
    }

    /**
     * Generate the Subscription object that would be returned by the SubscriptionService
     * @return the Subscription object
     */
    private Subscription fakeSubscriptionFromCache(boolean isExpired) {
        final Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan(PLAN_ID);
        if (isExpired) {
            subscription.setEndingAt(new Date(Instant.now().minus(1, HOURS).toEpochMilli()));
        }
        return subscription;
    }

    private String getJsonWebToken(long secondsToAdd) throws Exception {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
            .claim("client_id", CLIENT_ID)
            .expirationTime(Date.from(Instant.now().plusSeconds(secondsToAdd)))
            .build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(HMAC_HS256.getAlg()), jwtClaimsSet);
        signedJWT.sign(new MACSigner(JWT_SECRET));
        return signedJWT.serialize();
    }

    private void assert401unauthorized(TestObserver<HttpResponse<Buffer>> obs) {
        awaitTerminalEvent(obs)
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                assertUnauthorizedResponseBody(response.bodyAsString());
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
        return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
    }

    protected void assertUnauthorizedResponseBody(String responseBody) {
        assertThat(responseBody).isEqualTo("Unauthorized");
    }

    private SecurityToken securityTokenMatcher(String clientId) {
        return argThat(securityToken ->
            securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) && securityToken.getTokenValue().equals(clientId)
        );
    }
}
