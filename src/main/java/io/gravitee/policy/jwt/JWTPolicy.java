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

import com.sun.corba.se.impl.protocol.POALocalCRDImpl;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.exceptions.ValidationFromCacheException;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.Cache;
import io.gravitee.resource.cache.CacheResource;
import io.gravitee.resource.cache.Element;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.core.env.Environment;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("unused")
public class JWTPolicy {

    /**
     * Private JWT constants
     */
    private static final String BEARER = "Bearer";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String ISS = "iss";
    private static final String DEFAULT_KID = "default";
    private static final String PUBLIC_KEY_PROPERTY = "policy.jwt.issuer.%s.%s";
    private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");
    
    /**
     * The associated configuration to this JWT Policy
     */
    private JWTPolicyConfiguration configuration;
    private Cache cache;

    /**
     * Create a new JWT Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new JWT Policy instance
     */
    public JWTPolicy(JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }



    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        try {
            //1st extract the JWT to validate.
            String jwt = extractJsonWebToken(request);

            //2nd check if cache is enabled and if yes, check if JWT has already been validated.
            if(this.configuration.isUseValidationCache()) {
                try {
                    validateTokenFromCache(executionContext, jwt);
                }catch (ValidationFromCacheException e) {
                    policyChain.failWith(PolicyResult.failure(e.getMessage()));
                }
            }
            //3rd, if no cache is used, then just parse and validate it.
            else {
                validateJsonWebToken(executionContext, jwt);
            }

            //Finally continue the process...
            policyChain.doNext(request, response);

        } catch (ExpiredJwtException | MalformedJwtException | SignatureException e ) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));
        }
    }

    /**
     * Extract JWT from the request.
     * First attempt to extract if from standard Authorization header.
     * If none, then try to extract it from access_token query param.
     * @param request Request
     * @return String Json Web Token.
     */
    private String extractJsonWebToken(Request request) {
        final String authorization = request.headers().getFirst(HttpHeaders.AUTHORIZATION);
        String jwt;

        if (authorization != null) {
            jwt = authorization.substring(BEARER.length()).trim();
        } else {
            jwt = request.parameters().get(ACCESS_TOKEN);
        }

        return jwt;
    }

    private void validateTokenFromCache(ExecutionContext executionContext, String jwt) throws ValidationFromCacheException{

        //Get Cache
        CacheResource cacheResource = executionContext.getComponent(ResourceManager.class)
                .getResource(this.configuration.getCacheName(), CacheResource.class);

        if (cacheResource == null) {
            throw new ValidationFromCacheException("No cache has been defined with name " + this.configuration.getCacheName());
        }

        cache = cacheResource.getCache();
        if (cache == null) {
            throw new ValidationFromCacheException("No cache named [ " + this.configuration.getCacheName() + " ] has been found.");
        }

        //Get token expiration date from cache.
        Element cacheElement = cache.get(jwt);
        Instant expiration;
        if (cacheElement == null) {
            //If no token found in cache then parse/validate/cache it
            expiration = validateJsonWebToken(executionContext, jwt);
            addJsonWebTokenToCache(jwt, expiration);
        } else {
            //If token (cache key) exists in cache, check expiration time (cache value).
            expiration = (Instant) cacheElement.value();
            if (Instant.now().isAfter(expiration)) {
                throw new JwtException("Token expired!");
            }
        }
    }

    /**
     * This method is used to validate the JWT Token.
     * It will check the signature (by using the public RSA key linked to the JWT issuer)
     * Then it will check the expiration date provided in the token.
     * @param executionContext ExecutionContext used to retrieve the public RSA key.
     * @param jwt String Json Web Token
     * @return Instant expiration provided in the token (may be cached)
     */
    private Instant validateJsonWebToken(ExecutionContext executionContext, String jwt) {
        SigningKeyResolver resolver = new SigningKeyResolverAdapter() {

            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {

                String keyId = header.getKeyId(); //or any other field that you need to inspect
                final String iss = (String) claims.get(Claims.ISSUER);

                if (keyId == null || keyId.isEmpty()) {
                    keyId = DEFAULT_KID;
                }

                Environment env = executionContext.getComponent(Environment.class);
                return parsePublicKey(env.getProperty(String.format(PUBLIC_KEY_PROPERTY, iss, keyId)));
            }
        };

        final Jwt token = Jwts.parser().setSigningKeyResolver(resolver).parse(jwt);
        return ((DefaultClaims) token.getBody()).getExpiration().toInstant();
    }

    /**
     * Just fill the cache with as key the JWT and as value the expiration date.
     * @param jwt String Json Web Token
     * @param expiration Instant
     */
    private void addJsonWebTokenToCache(String jwt, Instant expiration) {
        cache.put(new Element() {
            @Override
            public Object key() {
                return jwt;
            }

            @Override
            public Object value() {
                return expiration;
            }
        });
    }

    static RSAPublicKey parsePublicKey(String key) {
        Matcher m = SSH_PUB_KEY.matcher(key);

        if (m.matches()) {
            String alg = m.group(1);
            String encKey = m.group(2);
            //String id = m.group(3);

            if (!"rsa".equalsIgnoreCase(alg)) {
                throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
            }

            return parseSSHPublicKey(encKey);
        }

        return null;
    }

    /**
     * <pre>
     * Each rsa key should start with xxxxssh-rsa and then contains two big integer (modulus & exponent) which are prime number.
     * The modulus & exponent are used to generate the RSA Public Key.
     * <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">See wiki explanations for deeper understanding</a>
     * </pre>
     * @param encKey String 
     * @return RSAPublicKey
     */
    private static RSAPublicKey parseSSHPublicKey(String encKey) {
        final byte[] PREFIX = new byte[] {0,0,0,7, 's','s','h','-','r','s','a'};
        ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(StandardCharsets.UTF_8.encode(encKey)).array());
        
        byte[] prefix = new byte[11];

        try {
            if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
                throw new IllegalArgumentException("SSH key prefix not found");
            }

            BigInteger e = new BigInteger(readBigInteger(in));//public exponent
            BigInteger n = new BigInteger(readBigInteger(in));//modulus

            return createPublicKey(n, e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * bytes are not in the good order, they are in the big endian format, we reorder them before reading them...
     * Each time you call this method, the buffer position will move, so result are differents...
     * @param in byte array of a public encryption key without 11 "xxxxssh-rsa" first byte.
     * @return BigInteger public exponent on first call, then modulus.
     * @throws IOException
     */
    private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
        byte[] b = new byte[4];

        if (in.read(b) != 4) {
            throw new IOException("Expected length data as 4 bytes");
        }

        int l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

        b = new byte[l];

        if (in.read(b) != l) {
            throw new IOException("Expected " + l + " key bytes");
        }

        return b;
    }
}
