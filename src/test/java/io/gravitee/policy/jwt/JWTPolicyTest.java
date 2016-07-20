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

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.Environment;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.Cache;
import io.gravitee.resource.cache.CacheResource;
import io.gravitee.resource.cache.Element;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTPolicyTest {

    private static final String ISS = "gravitee.authorization.server";
    private static final String KID = "MAIN";
    private static final String CACHE_NAME = "namedCache";
    
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
    private CacheResource cacheResource;
    @Mock
    private ResourceManager resourceManager;
    @Mock
    private Cache cache;
    @Mock
    private Element element;
    
    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void test_with_cache_disabled_and_valid_authorization_header() throws Exception {
        
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(false);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_valid_access_token() throws Exception {
        
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        Map<String,String> parameters = new HashMap<String,String>(1);
        parameters.put("access_token", jwt);

        when(request.headers()).thenReturn(new HttpHeaders());
        when(request.parameters()).thenReturn(parameters);
        when(configuration.isUseValidationCache()).thenReturn(false);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(request,times(1)).parameters();
        verify(policyChain,times(1)).doNext(request, response);
    }
    
    @Test
    public void test_with_cache_disabled_and_expired_header_token() throws Exception {

        String jwt = getJsonWebToken(0);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(false);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);
        
        verify(policyChain,Mockito.times(0)).doNext(request, response);
        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void test_with_cache_disabled_and_unknonw_issuer() throws Exception {
        
        String jwt = getJsonWebToken(7200,"unknown",null);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(false);
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);
        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
    }
    
    @Test
    public void test_with_cache_enabled_and_valid_expiration_date_cache() throws Exception {
        
        String jwt = "jwtUsedAsKeyCache";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(true);
        when(configuration.getCacheName()).thenReturn(CACHE_NAME);
        
        //TODO
        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(CACHE_NAME, CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache()).thenReturn(cache);
        when(cache.get(jwt)).thenReturn(element);
        when(element.value()).thenReturn(Instant.now().plusSeconds(7200));
       
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
    
    @Test(expected = JwtException.class)
    public void test_with_cache_enabled_and_non_valid_expiration_date_cache() throws Exception {
        
        String jwt = "jwtUsedAsKeyCache";

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(true);
        when(configuration.getCacheName()).thenReturn(CACHE_NAME);
        
        //TODO
        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(CACHE_NAME, CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache()).thenReturn(cache);
        when(cache.get(jwt)).thenReturn(element);
        when(element.value()).thenReturn(Instant.now().minusSeconds(1));
        
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,Mockito.times(1)).doNext(request, response);
    }
 
    @Test
    public void test_with_empty_cache_enabled_and_valid_jwt() throws Exception {
        
        String jwt = getJsonWebToken(7200);
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(true);
        when(configuration.getCacheName()).thenReturn(CACHE_NAME);
        
        //TODO
        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(CACHE_NAME, CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache()).thenReturn(cache);
        when(cache.get(jwt)).thenReturn(null);
        when(element.value()).thenReturn(Instant.now().plusSeconds(7200));
       
        JWTPolicy policy = new JWTPolicy(configuration);
        
        policy.onRequest(request, response, executionContext, policyChain);//1st time no cache found
        when(cache.get(jwt)).thenReturn(element);
        policy.onRequest(request, response, executionContext, policyChain);//2nd time cache found

        verify(cache,times(1)).put(any(Element.class));
        verify(policyChain,Mockito.times(2)).doNext(request, response);
    }
    
    @Test
    public void test_with_empty_cache_enabled_and_non_valid_jwt() throws Exception {
        
        String jwt = getJsonWebToken(0);
        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty("policy.jwt.issuer.gravitee.authorization.server.MAIN")).thenReturn(getSshRsaKey());
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer "+jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.isUseValidationCache()).thenReturn(true);
        when(configuration.getCacheName()).thenReturn(CACHE_NAME);
        
        //TODO
        when(executionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(CACHE_NAME, CacheResource.class)).thenReturn(cacheResource);
        when(cacheResource.getCache()).thenReturn(cache);
        when(cache.get(jwt)).thenReturn(null);
       
        new JWTPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain,times(1)).failWith(any(PolicyResult.class));
    }
    
    
    //PRIVATE tools method for tests
    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private String getJsonWebToken(long secondsToAdd) throws Exception {
        return getJsonWebToken(secondsToAdd,null,null);
    }
    
    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    private String getJsonWebToken(long secondsToAdd, String iss, String kid) throws Exception{

        Map<String,Object> header = new HashMap<String,Object>(2);
        header.put("alg", "RS256");
        header.put("kid", kid!=null?kid:KID);
        
        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setHeader(header);
        jwtBuilder.setSubject("alexluso");
        jwtBuilder.setIssuer(iss!=null?iss:ISS);
        jwtBuilder.setExpiration(Date.from(Instant.now().plusSeconds(secondsToAdd)));

        jwtBuilder.signWith(SignatureAlgorithm.RS256, getPrivateKey());
        return jwtBuilder.compact();
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
        File file = new File(getClass().getClassLoader().getResource("private_key.der").getFile());
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
