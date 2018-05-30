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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.expression.TemplateEngine;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.configuration.PublicKeyResolver;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.Environment;

import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
* @author Alexandre FARIA (alexandre82.faria at gmail.com)
*/
public class JWTPolicyTest {

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
    }

    @Test
    public void test_with_cache_disabled_and_gateway_keys_and_valid_authorization_header() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_client_id_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id");

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_aud_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, "my-client-id-from-aud");

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-aud");

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_aud_array_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, new String [] {"my-client-id-from-aud"});

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-aud");

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_azp_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, "my-client-id-from-azp");

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-azp");

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_with_multiple_client_claims() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUDIENCE, new String [] {"my-client-id-from-aud"});
        builder.claim(JWTPolicy.CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY, "my-client-id-from-azp");

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, "my-client-id-from-azp");

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_get_client_without_client_claim() throws Exception {
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());

        JwtBuilder builder = getJsonWebToken(7200);

        String jwt = builder.compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(executionContext,Mockito.times(1))
                .setAttribute(JWTPolicy.CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, null);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }

    @Test
    public void test_with_cache_disabled_and_given_key_and_valid_authorization_header() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(getSshRsaKey());
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(getSshRsaKey())).thenReturn(getSshRsaKey());
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_given_key_using_EL_and_valid_authorization_header() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();
        final String property = "prop['key']";
        
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(property);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(property)).thenReturn(getSshRsaKey());
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_given_key_but_not_provided() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_KEY);
        when(configuration.getResolverParameter()).thenReturn(null);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(0)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_gateway_keys_and_valid_access_token() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        MultiValueMap<String,String> parameters = new LinkedMultiValueMap<>(1);
        parameters.put("access_token", Collections.singletonList(jwt));

        when(request.headers()).thenReturn(new HttpHeaders());
        when(request.parameters()).thenReturn(parameters);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(request,times(1)).parameters();
        verify(policyChain,times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_gateway_keys_and_expired_header_token() throws Exception {

        String jwt = getJsonWebToken(0).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);
        
        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(0)).doNext(request, response);
    }

    @Test
    public void test_with_cache_disabled_and_gateway_keys_and_unknonw_issuer() throws Exception {
        
        String jwt = getJsonWebToken(7200,"unknown",null).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GATEWAY_KEYS);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);
        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(0)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_given_issuer_and_valid_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200).compact();
        final String resolverParameter = "validIss1|"+ISS+"|validIss3";
        
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_ISSUER);
        when(configuration.getResolverParameter()).thenReturn(resolverParameter);
        when(templateEngine.convert(resolverParameter)).thenReturn(resolverParameter);
 
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(0)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_given_issuer_using_EL_and_valid_authorization_header() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();
        final String property = "prop['key']";
        
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_ISSUER);
        when(configuration.getResolverParameter()).thenReturn(property);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(property)).thenReturn(ISS);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(0)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_given_issuer_but_not_provided() throws Exception {
        
        String jwt = getJsonWebToken(7200).compact();

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(PublicKeyResolver.GIVEN_ISSUER);
        when(configuration.getResolverParameter()).thenReturn(null);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
        verify(policyChain,Mockito.times(0)).doNext(request, response);
    }

    @Test
    public void test_not_authentifiction_scheme() throws Exception {

        String jwt = getJsonWebToken(7200).compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", jwt);
        when(request.headers()).thenReturn(headers);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void test_not_authentifiction_scheme_supported() throws Exception {

        String jwt = getJsonWebToken(7200).compact();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Basic " + jwt);
        when(request.headers()).thenReturn(headers);

        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
    }

    //PRIVATE tools method for tests
    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private JwtBuilder getJsonWebToken(long secondsToAdd) throws Exception {
        return getJsonWebToken(secondsToAdd,null,null);
    }
    
    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private JwtBuilder getJsonWebToken(long secondsToAdd, String iss, String kid) throws Exception{

        Map<String,Object> header = new HashMap<String,Object>(2);
        header.put("alg", "RS256");
        header.put("kid", kid!=null?kid:KID);
        
        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setHeader(header);
        jwtBuilder.setSubject("alexluso");
        jwtBuilder.setIssuer(iss!=null?iss:ISS);
        jwtBuilder.setExpiration(Date.from(Instant.now().plusSeconds(secondsToAdd)));

        jwtBuilder.signWith(SignatureAlgorithm.RS256, getPrivateKey());

        return jwtBuilder;
    }
    
    /**
     * How to generate keys?
     * Run : ssh-keygen -t rsa -C "alex.luso@myCompany.com"
     * ==> Will create id_rsa & id_rsa.pub
     * Then run : openssl pkcs8 -topk8 -inform PEM -outform DER -in id_rsa -out private_key.der -nocrypt
     * ==> Will create private_key.der unsecured that can be used.
     * @return
     * @throws Exception
     */
    private PrivateKey getPrivateKey() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("private_key.der").toURI());
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        return kf.generatePrivate(spec);
    }
    
    /**
     * Return string value of public key matching format ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)
     * @return String
     * @throws IOException
     */
    private String getSshRsaKey() throws IOException {
        InputStream input = getClass().getClassLoader().getResourceAsStream("id_rsa.pub");
        BufferedReader buffer = new BufferedReader(new InputStreamReader(input));
        return buffer.lines().collect(Collectors.joining("\n"));
    }
}
