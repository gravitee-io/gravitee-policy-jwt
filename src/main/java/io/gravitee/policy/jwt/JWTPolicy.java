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
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.exceptions.InvalidTokenException;
import io.gravitee.policy.jwt.jwks.URLJWKSourceResolver;
import io.gravitee.policy.jwt.jwks.hmac.MACJWKSourceResolver;
import io.gravitee.policy.jwt.jwks.retriever.VertxResourceRetriever;
import io.gravitee.policy.jwt.jwks.rsa.RSAJWKSourceResolver;
import io.gravitee.policy.jwt.processor.AbstractKeyProcessor;
import io.gravitee.policy.jwt.processor.HMACKeyProcessor;
import io.gravitee.policy.jwt.processor.JWKSKeyProcessor;
import io.gravitee.policy.jwt.processor.RSAKeyProcessor;
import io.gravitee.policy.jwt.resolver.*;
import io.gravitee.policy.jwt.token.TokenExtractor;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTPolicy.class);

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

    static final String JWT_MISSING_TOKEN_KEY = "JWT_MISSING_TOKEN";
    static final String JWT_INVALID_TOKEN_KEY = "JWT_INVALID_TOKEN";

    /**
     * Error message format
     */
    static final String errorMessageFormat = "[request-id:%s] [request-path:%s] %s";

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
                            if (throwable.getCause() instanceof InvalidTokenException) {
                                LOGGER.debug(String.format(errorMessageFormat, request.id(), request.path(), throwable.getMessage()), throwable.getCause());
                                request.metrics().setMessage(throwable.getCause().getCause().getMessage());
                            } else {
                                LOGGER.error(String.format(errorMessageFormat, request.id(), request.path(), throwable.getMessage()), throwable.getCause());
                                request.metrics().setMessage(throwable.getCause().getMessage());
                            }
                            policyChain.failWith(PolicyResult.failure(
                                    JWT_INVALID_TOKEN_KEY,
                                    HttpStatusCode.UNAUTHORIZED_401,
                                    UNAUTHORIZED_MESSAGE));
                        }
                        else {
                            // 3_ Set access_token in context
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_TOKEN, jwt);

                            String clientId = getClientId(claims);
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, clientId);
                            executionContext.setAttribute(ATTR_USER, claims.getSubject());

                            if (configuration.isExtractClaims()) {
                                executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
                            }

                            // Finally continue the process...
                            policyChain.doNext(request, response);
                        }
                    });

            if (!configuration.isPropagateAuthHeader()) {
                request.headers().remove(HttpHeaders.AUTHORIZATION);
            }
        } catch (Exception e) {
            LOGGER.error(String.format(errorMessageFormat, request.id(), request.path(), e.getMessage()), e.getCause());
            policyChain.failWith(PolicyResult.failure(
                    JWT_MISSING_TOKEN_KEY,
                    HttpStatusCode.UNAUTHORIZED_401,
                    UNAUTHORIZED_MESSAGE));
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
        final Signature signature = (configuration.getSignature() == null)
                ? Signature.RSA_RS256 : configuration.getSignature();

        AbstractKeyProcessor keyProcessor = null;

        if (configuration.getPublicKeyResolver() != KeyResolver.JWKS_URL) {
            SignatureKeyResolver signatureKeyResolver;
            switch (configuration.getPublicKeyResolver()) {
                case GIVEN_KEY:
                    signatureKeyResolver = new TemplatableSignatureKeyResolver(
                            executionContext.getTemplateEngine(),
                            new UserDefinedSignatureKeyResolver(configuration.getResolverParameter()));
                    break;
                case GATEWAY_KEYS:
                    signatureKeyResolver = new GatewaySignatureKeyResolver(
                            executionContext.getComponent(Environment.class),
                            token);
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected signature key resolver");
            }

            switch (signature) {
                case RSA_RS256:
                case RSA_RS384:
                case RSA_RS512:
                    keyProcessor = new RSAKeyProcessor();
                    keyProcessor.setJwkSourceResolver(new RSAJWKSourceResolver(signatureKeyResolver));
                    break;
                case HMAC_HS256:
                case HMAC_HS384:
                case HMAC_HS512:
                    keyProcessor = new HMACKeyProcessor();
                    keyProcessor.setJwkSourceResolver(new MACJWKSourceResolver(signatureKeyResolver));
                    break;
            }


        } else {
            keyProcessor = new JWKSKeyProcessor();
            keyProcessor.setJwkSourceResolver(new URLJWKSourceResolver(
                    configuration.getResolverParameter(),
                    new VertxResourceRetriever(executionContext.getComponent(Vertx.class))));
        }

        return keyProcessor.process(signature, token);
    }
}
