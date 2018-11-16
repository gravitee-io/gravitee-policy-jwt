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

import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwks.PublicKeyJWKSourceResolver;
import io.gravitee.policy.jwt.jwks.URLJWKSourceResolver;
import io.gravitee.policy.jwt.jwks.retriever.VertxResourceRetriever;
import io.gravitee.policy.jwt.key.GatewayPublicKeyResolver;
import io.gravitee.policy.jwt.key.TemplatablePublicKeyResolver;
import io.gravitee.policy.jwt.key.UserDefinedPublicKeyResolver;
import io.gravitee.policy.jwt.processor.AbstractKeyProcessor;
import io.gravitee.policy.jwt.processor.JWKSKeyProcessor;
import io.gravitee.policy.jwt.processor.PublicKeyKeyProcessor;
import io.gravitee.policy.jwt.token.TokenExtractor;
import io.vertx.core.Vertx;
import org.springframework.core.env.Environment;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy {

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

    static final String UNAUTHORIZED_MESSAGE = "Unauthorized";

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
            // 1_ Extract the JWT from HTTP request headers or query-parameters
            final String jwt = TokenExtractor.extract(request);

            // 2_ Validate the token algorithm + signature
            validate(executionContext, jwt)
                    .whenComplete((claims, throwable) -> {
                        if (throwable != null) {
                            request.metrics().setMessage(throwable.getCause().getCause().getMessage());
                            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, UNAUTHORIZED_MESSAGE));
                        }
                        else {
                            // 3_ Set access_token in context
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_TOKEN, jwt);

                            String clientId = getClientId(claims);
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, clientId);

                            if (configuration.isExtractClaims()) {
                                executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
                            }

                            // Finally continue the process...
                            policyChain.doNext(request, response);
                        }
                    });

        } catch (Exception ex) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, UNAUTHORIZED_MESSAGE));
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

    private CompletableFuture<JWTClaimsSet> validate(ExecutionContext executionContext, String token) throws Exception {
        AbstractKeyProcessor keyProcessor;

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
            case JWKS_URL:
                keyProcessor = new JWKSKeyProcessor(new URLJWKSourceResolver(
                        configuration.getResolverParameter(),
                        new VertxResourceRetriever(executionContext.getComponent(Vertx.class))));
                break;
            default:
                throw new IllegalArgumentException("Unexpected key resolver value.");
        }

        return keyProcessor.process(token);
    }
}
