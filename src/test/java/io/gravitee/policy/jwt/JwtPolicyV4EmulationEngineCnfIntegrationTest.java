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
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.gravitee.policy.jwt.alg.Signature.HMAC_HS256;
import static io.gravitee.policy.v3.jwt.resolver.KeyResolver.GIVEN_KEY;
import static java.util.concurrent.TimeUnit.HOURS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientResponse;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author GraviteeSource Team
 */
public class JwtPolicyV4EmulationEngineCnfIntegrationTest {

    public static final Map<String, Object> EXTRA_CNF_CLAIM = Map.of(
        "cnf",
        Map.of("x5t#S256", "2oHrNOqScxD8EHkb7_GYmnNvWqGj5M31Dqsrk3Jl2Yk")
    );
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

    public static void configureHttpClient(HttpClientOptions options, int gatewayPort) {
        options.setDefaultHost("localhost").setDefaultPort(gatewayPort).setSsl(true).setVerifyHost(false).setTrustAll(true);
    }

    public static void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
        gatewayConfigurationBuilder
            .set("http.secured", true)
            .set("http.alpn", true)
            .set("http.ssl.keystore.type", "self-signed")
            .set("http.ssl.clientAuth", "request")
            .set("http.ssl.truststore.type", "pkcs12")
            .set(
                "http.ssl.truststore.path",
                JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/keystore.p12").getPath()
            )
            .set("http.ssl.truststore.password", "gravitee");
    }

    public static Subscription fakeSubscriptionFromCache(boolean isExpired) {
        final Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan(PLAN_ID);
        if (isExpired) {
            subscription.setEndingAt(new Date(Instant.now().minus(1, HOURS.toChronoUnit()).toEpochMilli()));
        }
        return subscription;
    }

    public static SecurityToken securityTokenMatcher(String clientId) {
        return argThat(securityToken ->
            securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) && securityToken.getTokenValue().equals(clientId)
        );
    }

    public static Plan createPlan(final Api api) {
        Plan jwtPlan = new Plan();
        jwtPlan.setId(PLAN_ID);
        jwtPlan.setApi(api.getId());
        jwtPlan.setSecurity("JWT");
        jwtPlan.setStatus("PUBLISHED");
        return jwtPlan;
    }

    public static String getJsonWebToken(Map<String, Object> extraClaims) throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .claim("client_id", CLIENT_ID)
            .expirationTime(Date.from(Instant.now().plusSeconds(5000)));
        if (extraClaims != null) {
            extraClaims.forEach(builder::claim);
        }
        JWTClaimsSet jwtClaimsSet = builder.build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(HMAC_HS256.getAlg()), jwtClaimsSet);
        signedJWT.sign(new MACSigner(JWT_SECRET));
        return signedJWT.serialize();
    }

    public static void assert401unauthorized(WireMockServer wiremock, Single<HttpClientResponse> httpClientResponse)
        throws InterruptedException {
        httpClientResponse
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Nested
    @GatewayTest
    @DeployApi("/apis/jwt.json")
    public class JwtPolicyV4EmulationEngineMissingCnfIntegrationTest extends AbstractJwtPolicyMissingCnfIntegrationTest {}

    public static class AbstractJwtPolicyMissingCnfIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan jwtPlan = createPlan(api);

            JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
            configuration.setSignature(HMAC_HS256);
            configuration.setResolverParameter(JWT_SECRET);
            configuration.setPublicKeyResolver(GIVEN_KEY);
            configuration.getConfirmationMethodValidation().setIgnoreMissing(true);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);
            try {
                jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set JWT policy configuration", e);
            }

            api.setPlans(Collections.singletonList(jwtPlan));
        }

        @Test
        void should_access_api_and_ignore_missing_cnf(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(null);

            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).rxSend())
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/jwt.json")
    @GatewayTest
    public class JwtPolicyV4EmulationEngineCnfHeaderCertificateIntegrationTest
        extends AbstractJwtPolicyCnfHeaderCertificateIntegrationTest {}

    public static class AbstractJwtPolicyCnfHeaderCertificateIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan jwtPlan = createPlan(api);

            JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
            configuration.setSignature(HMAC_HS256);
            configuration.setResolverParameter(JWT_SECRET);
            configuration.setPublicKeyResolver(GIVEN_KEY);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setExtractCertificateFromHeader(true);

            try {
                jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set JWT policy configuration", e);
            }

            api.setPlans(Collections.singletonList(jwtPlan));
        }

        @Test
        void should_access_api_with_valid_certificate_from_header(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(EXTRA_CNF_CLAIM);
            String clientCert = Files.readString(
                Paths.get(JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/client1-crt.pem").toURI())
            );
            String encoded = URLEncoder.encode(clientCert, Charset.defaultCharset());

            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).putHeader("ssl-client-cert", encoded).rxSend())
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        @Test
        void should_return_401_without_valid_certificate_in_header(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));
            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(EXTRA_CNF_CLAIM);

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).putHeader("ssl-client-cert", "wrong").rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        @Test
        void should_return_401_with_valid_certificate_in_header_but_without_cnf_in_token(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));
            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(null);
            String clientCert = Files.readString(
                Paths.get(JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/client1-crt.pem").toURI())
            );
            String encoded = URLEncoder.encode(clientCert, Charset.defaultCharset());

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).putHeader("ssl-client-cert", encoded).rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/jwt.json")
    @GatewayTest
    public class JwtPolicyV4EmulationEngineCnfPeerCertificateIntegrationTest extends AbstractJwtPolicyCnfPeerCertificateIntegrationTest {}

    public static class AbstractJwtPolicyCnfPeerCertificateIntegrationTest extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());

            final PemKeyCertOptions pemKeyCertOptions = new PemKeyCertOptions();
            pemKeyCertOptions.setCertPath(
                JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/client1-crt.pem").getPath()
            );
            pemKeyCertOptions.setKeyPath(
                JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/client1-key.pem").getPath()
            );
            options.setPemKeyCertOptions(pemKeyCertOptions);
        }

        @Override
        public void configureApi(final Api api) {
            Plan jwtPlan = createPlan(api);

            JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
            configuration.setSignature(HMAC_HS256);
            configuration.setResolverParameter(JWT_SECRET);
            configuration.setPublicKeyResolver(GIVEN_KEY);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);

            try {
                jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set JWT policy configuration", e);
            }

            api.setPlans(Collections.singletonList(jwtPlan));
        }

        @Test
        void should_access_api_with_valid_certificate_from_ssl_session(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(EXTRA_CNF_CLAIM);
            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).rxSend())
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        @Test
        void should_return_401_with_valid_certificate_from_ssl_session_but_without_cnf_in_token(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(null);
            String clientCert = Files.readString(
                Paths.get(JwtPolicyV4EmulationEngineCnfIntegrationTest.class.getResource("/client/client1-crt.pem").toURI())
            );
            String encoded = URLEncoder.encode(clientCert, Charset.defaultCharset());

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).putHeader("ssl-client-cert", encoded).rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/jwt.json")
    @GatewayTest
    public class JwtPolicyV4EmulationEngineCnfInvalidPeerCertificateIntegrationTest
        extends AbstractJwtPolicyCnfInvalidPeerCertificateIntegrationTest {}

    public static class AbstractJwtPolicyCnfInvalidPeerCertificateIntegrationTest
        extends AbstractPolicyTest<JWTPolicy, JWTPolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            JwtPolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan jwtPlan = createPlan(api);

            JWTPolicyConfiguration configuration = new JWTPolicyConfiguration();
            configuration.setSignature(HMAC_HS256);
            configuration.setResolverParameter(JWT_SECRET);
            configuration.setPublicKeyResolver(GIVEN_KEY);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);

            try {
                jwtPlan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set JWT policy configuration", e);
            }

            api.setPlans(Collections.singletonList(jwtPlan));
        }

        @Test
        void should_return_401_without_valid_peer_certificate_from_ssl_session(HttpClient client) throws Exception {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String jwtToken = getJsonWebToken(EXTRA_CNF_CLAIM);
            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + jwtToken).rxSend());

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }
}
