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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.resolver.KeyResolver;
import io.gravitee.reporter.api.http.Metrics;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.Environment;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * @author Alexandre FARIA (alexandre82.faria at gmail.com)
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public abstract class JWTPolicyTest {

    private static final String ISS = "gravitee.authorization.server";
    private static final String KID = "MAIN";

    @Mock
    private ExecutionContext executionContext;
    @Mock
    private Environment environment;
    @Mock
    private Request request;
    @Mock
    private Response response;
    @Mock
    private PolicyChain policyChain;
    @Mock
    private JWTPolicyConfiguration configuration;
    @Mock
    TemplateEngine templateEngine;
    
    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
        when(request.metrics()).thenReturn(Metrics.on(System.currentTimeMillis()).build());
        when(configuration.getSignature()).thenReturn(getSignature());
    }

    @Test
    public void test_with_gateway_keys_and_valid_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());
        
        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_with_gateway_keys_and_valid_lowercase_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_client_id_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_unsigned_jwt() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");

        String jwt = sign(builder.build());

        jwt = jwt.substring(0, jwt.lastIndexOf('.')+1);
        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && JWTPolicy.JWT_INVALID_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }

    @Test
    public void test_get_client_with_aud_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, "my-client-id-from-aud");

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-aud");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_configuration() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, "my-client-id-from-aud");
        builder.claim("configuration_client_id", "my-client-id-from-configuration");

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);
        when(configuration.getClientIdClaim()).thenReturn("configuration_client_id");

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-configuration");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_configuration_array() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, "my-client-id-from-aud");
        builder.claim("configuration_client_id", Collections.singletonList("my-client-id-from-configuration"));

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);
        when(configuration.getClientIdClaim()).thenReturn("configuration_client_id");

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-configuration");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_aud_array_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.audience(Collections.singletonList("my-client-id-from-aud"));

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-aud");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_azp_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, "my-client-id-from-azp");

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-azp");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_multiple_client_claims() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, new String [] {"my-client-id-from-aud"});
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, "my-client-id-from-azp");

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-azp");

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_without_client_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(executionContext, times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, null);

        verify(policyChain, times(1)).doNext(request, response);
    }

    @Test
    public void test_with_given_key_and_valid_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(getSignatureKey());
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(getSignatureKey(), String.class)).thenReturn(getSignatureKey());

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_given_key_using_EL_and_valid_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200);
        final String property = "prop['key']";
        
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(property);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.getValue(property, String.class)).thenReturn(getSignatureKey());

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_given_key_but_not_provided() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(null);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_MISSING_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }
    
    @Test
    public void test_with_gateway_keys_and_valid_access_token() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());
        
        MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>(1);
        parameters.put("access_token", Collections.singletonList(jwt));

        when(request.headers()).thenReturn(HttpHeaders.create());
        when(request.parameters()).thenReturn(parameters);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(request, times(2)).parameters();
        verify(policyChain, times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_gateway_keys_and_expired_header_token() throws Exception {
        String jwt = getJsonWebToken(0);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);
        
        verify(policyChain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_INVALID_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }

    @Test
    public void test_with_gateway_keys_and_unknown_issuer() throws Exception {
        String jwt = getJsonWebToken(7200,"unknown");

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_MISSING_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }

    @Test
    public void test_not_authentification_scheme() throws Exception {
        String jwt = getJsonWebToken(7200);

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", jwt);
        when(request.headers()).thenReturn(headers);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_MISSING_TOKEN_KEY.equals(result.key())));
    }

    @Test
    public void test_not_authentification_scheme_supported() throws Exception {
        String jwt = getJsonWebToken(7200);

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Basic " + jwt);
        when(request.headers()).thenReturn(headers);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_MISSING_TOKEN_KEY.equals(result.key())));
    }

    @Test
    public void test_with_processing_error() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSignatureKey());

        JWTClaimsSet.Builder builder = getJsonWebTokenBuilder(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.audience(Collections.singletonList("my-client-id-from-aud"));

        String jwt = sign(builder.build());

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GATEWAY_KEYS);
        when(configuration.getUserClaim()).thenReturn("aud");

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_INVALID_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }

    @Test
    public void test_with_jwks_url() throws Exception {
        String jwksUrl = "https://{#dictionaries['myauthdomains']['test']}.com";
        String jwt = getJsonWebToken(7200);

        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);

        HttpHeaders headers = HttpHeaders.create()
                .set("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.JWKS_URL);
        when(configuration.getResolverParameter()).thenReturn(jwksUrl);
        when(templateEngine.getValue(jwksUrl, String.class)).thenReturn("https://test.com");

        executePolicy(configuration, request, response, executionContext, policyChain);

        // Here we expect that JWKSet resource has not been retrieved and so we finally get a 401.
        // Note: VertxResourceRetriever is hard to mock and throws an NPE (that's why we get a 401).
        verify(policyChain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                        && JWTPolicy.JWT_MISSING_TOKEN_KEY.equals(result.key())));
        verify(policyChain, never()).doNext(request, response);
    }

    private void executePolicy(JWTPolicyConfiguration configuration, Request request, Response response,
                               ExecutionContext executionContext, PolicyChain policyChain) throws InterruptedException {
        final CountDownLatch lock = new CountDownLatch(1);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        lock.await(50, TimeUnit.MILLISECONDS);
    }

    //PRIVATE tools method for tests
    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private String getJsonWebToken(long secondsToAdd) throws Exception {
        return sign(getJsonWebTokenBuilder(secondsToAdd, null).build());
    }

    private JWTClaimsSet.Builder getJsonWebTokenBuilder(long secondsToAdd) throws Exception {
        return getJsonWebTokenBuilder(secondsToAdd, null);
    }

    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private String getJsonWebToken(long secondsToAdd, String iss) throws Exception {
        return sign(getJsonWebTokenBuilder(secondsToAdd, iss).build());
    }

    private JWTClaimsSet.Builder getJsonWebTokenBuilder(long secondsToAdd, String iss) throws Exception {
        // Prepare JWT with claims set
        return new JWTClaimsSet.Builder()
                .subject("alexluso")
                .issuer(iss != null ? iss : ISS)
                .expirationTime(Date.from(Instant.now().plusSeconds(secondsToAdd)));
    }

    private String sign(JWTClaimsSet claimsSet) throws Exception {
        return sign(claimsSet, null);
    }

    private String sign(JWTClaimsSet claimsSet, String kid) throws Exception {
        JWSSigner signer = getSigner();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(getSignature().getAlg())
                        .keyID(kid != null ? kid : KID)
                        .build(),
                claimsSet);

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    abstract Signature getSignature();
    abstract JWSSigner getSigner() throws Exception;
    abstract String getSignatureKey() throws Exception;
}
