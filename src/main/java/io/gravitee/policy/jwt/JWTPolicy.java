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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.exceptions.ValidationFromCacheException;
import io.gravitee.repository.cache.api.CacheManager;
import io.gravitee.repository.cache.model.Cache;
import io.gravitee.repository.cache.model.Element;
import io.gravitee.repository.exceptions.CacheException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.DefaultClaims;

/**
* @author Alexandre FARIA (alexandre82.faria at gmail.com)
*/
public class JWTPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTPolicy.class);

    
    /**
     * Private JWT constants
     */
    private static final String BEARER = "Bearer";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String DEFAULT_KID = "default";
    private static final String PUBLIC_KEY_PROPERTY = "policy.jwt.issuer.%s.%s";
    private static final String CACHE_NAME = "JWT_CACHE";//must be also set into your distributed cache settings (ex :hazelcast.xml)
    private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");
    private static final Pattern PIPE_SPLIT_ISSUER = Pattern.compile("\\|");
    
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
                validateTokenFromCache(executionContext, jwt);
            }
            //3rd, if no cache is used, then just parse and validate it.
            else {
                validateJsonWebToken(executionContext, jwt);
            }

            //Finally continue the process...
            policyChain.doNext(request, response);

        }
        catch (ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e ) {
            LOGGER.error(e.getMessage(),e.getCause());
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

    private void validateTokenFromCache(ExecutionContext executionContext, String jwt) {
        try {
            // Get Cache
            CacheManager cacheManager = executionContext.getComponent(CacheManager.class);
            if (cacheManager == null) {
                throw new ValidationFromCacheException("No cache manager has been found");
            }

            cache = cacheManager.getCache(CACHE_NAME);
            if (cache == null) {
                throw new ValidationFromCacheException("No cache named [ " + CACHE_NAME + " ] has been found.");
            }

            // Get token expiration date from cache.
            Element cacheElement = cache.get(jwt);
            Instant expiration;
            if (cacheElement == null) {
                // If no token found in cache then parse/validate/cache it
                expiration = validateJsonWebToken(executionContext, jwt);
                cache.put(Element.from(jwt, expiration));
            } else {
                // If token (cache key) exists in cache, check expiration time (cache value).
                expiration = (Instant) cacheElement.value();
                if (Instant.now().isAfter(expiration)) {
                    throw new JwtException("Token expired!");
                }
            }
        }
        // If Cache is not correctly set or active, then do not break the policy
        catch (ValidationFromCacheException | CacheException e) {
            LOGGER.warn("Problem occurs on cache access, token is validated throught public key! Error is : "+e.getMessage());
            validateJsonWebToken(executionContext, jwt);
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
        
        JwtParser jwtParser = Jwts.parser();
        
        switch (configuration.getPublicKeyResolver()) {
            case GIVEN_KEY:
                jwtParser.setSigningKey(getPublickKeyByPolicySettings(executionContext));//Use key set into the policy
                break;
            case GIVEN_ISSUER:
                jwtParser.setSigningKeyResolver(getSigningKeyResolverByPolicyIssuer(executionContext));
                break;
            case GATEWAY_KEYS:
                jwtParser.setSigningKeyResolver(getSigningKeyResolverByGatewaySettings(executionContext));
                break;
            default:
                throw new IllegalArgumentException("Unexpected public key resolver value.");
        }
        
        final Jwt token = jwtParser.parse(jwt);
        return ((DefaultClaims) token.getBody()).getExpiration().toInstant();
    }
    
    /**
     * Return a SigingKeyResolver which will read iss claims value in order to get the associated public key.
     * The associated public keys are set into the gateway settings and retrieved thanks to ExecutionContext.
     * @param executionContext ExecutionContext
     * @return SigningKeyResolver
     */
    private SigningKeyResolver getSigningKeyResolverByGatewaySettings(ExecutionContext executionContext) {
        return new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {

                String keyId = header.getKeyId(); //or any other field that you need to inspect
                final String iss = (String) claims.get(Claims.ISSUER);

                if (keyId == null || keyId.isEmpty()) {
                    keyId = DEFAULT_KID;
                }

                Environment env = executionContext.getComponent(Environment.class);
                String publicKey = env.getProperty(String.format(PUBLIC_KEY_PROPERTY, iss, keyId));
                if(publicKey==null || publicKey.trim().isEmpty()) {
                    return null;
                }
                return parsePublicKey(publicKey);
            }
        }; 
    }

    /**
     * Return a SigingKeyResolver which will read iss claims value in order to get the associated public key.
     * The associated public keys are set into the gateway settings and retrieved thanks to ExecutionContext.
     * @param executionContext ExecutionContext
     * @return SigningKeyResolver
     */
    private SigningKeyResolver getSigningKeyResolverByPolicyIssuer(ExecutionContext executionContext) {
     
        if(configuration.getResolverParameter()==null || configuration.getResolverParameter().trim().isEmpty()) {
            throw new IllegalArgumentException("missing issuer into the policy settings");
        }
        
        return new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {

                //ISSUER management
                final String iss = (String) claims.get(Claims.ISSUER);
                
                // Given issuer can be defined as the template using EL
                LOGGER.debug("Transform given issuer {} using template engine", configuration.getResolverParameter());
                final String givenIssuers = executionContext.getTemplateEngine().convert(configuration.getResolverParameter());
                
                //check jwt issuer belongs to allowed policy issuers.
                boolean isValidIssuer = PIPE_SPLIT_ISSUER.splitAsStream(givenIssuers).anyMatch(s -> s.equals(iss));
                
                //no public key must be retrieved when issuer is not expected.
                if(!isValidIssuer) {
                    return null;
                }
                
                //KID (Key ID) management
                String keyId = header.getKeyId(); //or any other field that you need to inspect
                if (keyId == null || keyId.trim().isEmpty()) {
                    keyId = DEFAULT_KID;
                }

                //Get the public key from the gateway settings.
                Environment env = executionContext.getComponent(Environment.class);
                String publicKey = env.getProperty(String.format(PUBLIC_KEY_PROPERTY, iss, keyId));
                if(publicKey==null || publicKey.trim().isEmpty()) {
                    return null;
                }
                return parsePublicKey(publicKey);
            }
        }; 
    }    
    
    /**
     * Return RSA public key set into the policy settings.
     * @param executionContext ExecutionContext
     * @return RSAPublicKey
     */
    private RSAPublicKey getPublickKeyByPolicySettings(ExecutionContext executionContext) {
        String givenKey = configuration.getResolverParameter();
        if(givenKey==null || givenKey.trim().isEmpty()) {
            throw new IllegalArgumentException("No specified given key while expecting it due to policy settings.");
        }
        
        // Given key can be defined as the template using EL
        LOGGER.debug("Transform given key {} using template engine", givenKey);
        givenKey = executionContext.getTemplateEngine().convert(givenKey);
        return parsePublicKey(givenKey);
    }
    
    /**
     * Generate RSA Public Key from the ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*) stored key.
     * @param key String.
     * @return RSAPublicKey
     */
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
