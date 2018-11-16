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

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.exceptions.AuthSchemeException;
import io.gravitee.policy.jwt.jwks.PublicKeyJWKSourceResolver;
import io.gravitee.policy.jwt.key.GatewayPublicKeyResolver;
import io.gravitee.policy.jwt.key.TemplatablePublicKeyResolver;
import io.gravitee.policy.jwt.key.UserDefinedPublicKeyResolver;
import io.gravitee.policy.jwt.processor.KeyProcessor;
import io.gravitee.policy.jwt.processor.PublicKeyKeyProcessor;
import org.springframework.core.env.Environment;

import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy {

    /**
     * Private JWT constants
     */
    private static final String BEARER = "Bearer";
    private static final String ACCESS_TOKEN = "access_token";

    /**
     * Request attributes
     */
    static final String CONTEXT_ATTRIBUTE_PREFIX = "jwt.";
    static final String CONTEXT_ATTRIBUTE_JWT_CLAIMS = CONTEXT_ATTRIBUTE_PREFIX + "claims";
    static final String CONTEXT_ATTRIBUTE_JWT_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "token";
    static final String CONTEXT_ATTRIBUTE_CLIENT_ID = "client_id";
    static final String CONTEXT_ATTRIBUTE_AUDIENCE = "aud";
    static final String CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY = "azp";

    static final String CONTEXT_ATTRIBUTE_OAUTH_PREFIX = "oauth.";
    static final String CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID = CONTEXT_ATTRIBUTE_OAUTH_PREFIX + CONTEXT_ATTRIBUTE_CLIENT_ID;

    /**
     * The associated configuration to this JWT Policy
     */
    private JWTPolicyConfiguration configuration;
    
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
            // 1) extract the JWT from HTTP request headers
            String jwt = extractToken(request);

            // 2) validate the token algorithm + signature
            JWTClaimsSet claims = validate(executionContext, jwt);

            //3rd set access_token in context
            executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_TOKEN, jwt);

            String clientId = getClientId(claims);
            executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, clientId);

            if (configuration.isExtractClaims()) {
                executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
            }

            // Finally continue the process...
            policyChain.doNext(request, response);
        } catch (BadJOSEException e) {
            request.metrics().setMessage(e.getMessage());
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));
        } catch (Exception ex) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));
        }
    }

    private String getClientId(JWTClaimsSet claims) {
        String clientId = null;

        // Look for the OAuth2 client_id of the Relying Party from the Authorized party claim
        String authorizedParty = (String) claims.getClaim(CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY);
        if (authorizedParty != null && ! authorizedParty.isEmpty()) {
            clientId = authorizedParty;
        }

        if (clientId == null) {
            // Look for the OAuth2 client_id of the Relying Party from the audience claim
            Object audClaim = claims.getClaim(CONTEXT_ATTRIBUTE_AUDIENCE);
            if (audClaim != null) {
                if (audClaim instanceof List) {
                    List<String> audiences = (List<String>) audClaim;
                    // For the moment, we took only the first value of the array
                    clientId = audiences.get(0);
                } else {
                    clientId = (String) audClaim;
                }
            }
        }

        // Is there any client_id claim in JWT claims ?
        if (clientId == null) {
            clientId = (String) claims.getClaim(CONTEXT_ATTRIBUTE_CLIENT_ID);
        }

        return clientId;
    }

    /**
     * Extract JWT from the request.
     * First attempt to extract if from standard Authorization header.
     * If none, then try to extract it from access_token query param.
     * @param request Request
     * @return String Json Web Token.
     */
    private String extractToken(Request request) throws AuthSchemeException {
        final String authorization = request.headers().getFirst(HttpHeaders.AUTHORIZATION);
        String jwt;

        if (authorization != null) {
            String[] auth = authorization.split(" ");
            if(auth.length > 1 && BEARER.equals(auth[0])) {
                jwt = auth[1].trim();
            } else if(auth.length > 1){
                throw new AuthSchemeException("Authentification scheme '" + auth[0] + "' is not supported for JWT");
            } else {
                throw new AuthSchemeException("Authentification scheme not found");
            }

        } else {
            jwt = request.parameters().getFirst(ACCESS_TOKEN);
        }

        return jwt;
    }

    /**
     * This method is used to validate the JWT Token.
     * It will check the signature (by using the public RSA key linked to the JWT issuer)
     * @param executionContext ExecutionContext used to retrieve the public RSA key.
     * @param token String Json Web Token
     * @return DefaultClaims claims extracted from JWT body
     */
    private JWTClaimsSet validate(ExecutionContext executionContext, String token) throws Exception {
        KeyProcessor keyProcessor;

        switch (configuration.getPublicKeyResolver()) {
            case GIVEN_KEY:
                keyProcessor = new PublicKeyKeyProcessor(new PublicKeyJWKSourceResolver(
                        new TemplatablePublicKeyResolver(
                                executionContext.getTemplateEngine(),
                                new UserDefinedPublicKeyResolver(configuration.getResolverParameter()))));
                break;
            case GATEWAY_KEYS:
                keyProcessor = new PublicKeyKeyProcessor(new PublicKeyJWKSourceResolver(
                        new GatewayPublicKeyResolver(executionContext.getComponent(Environment.class), token)));
                break;
            default:
                throw new IllegalArgumentException("Unexpected key resolver value.");
        }

        return keyProcessor.process(token);
    }
}
