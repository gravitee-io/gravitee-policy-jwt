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
package io.gravitee.policy.v3.jwt;

import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;

import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.security.CertificateUtils;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.utils.TokenExtractor;
import io.gravitee.policy.v3.jwt.exceptions.InvalidCertificateThumbprintException;
import io.gravitee.policy.v3.jwt.exceptions.InvalidTokenException;
import io.gravitee.policy.v3.jwt.jwks.URLJWKSourceResolver;
import io.gravitee.policy.v3.jwt.jwks.hmac.MACJWKSourceResolver;
import io.gravitee.policy.v3.jwt.jwks.retriever.RetrieveOptions;
import io.gravitee.policy.v3.jwt.jwks.retriever.VertxResourceRetriever;
import io.gravitee.policy.v3.jwt.jwks.rsa.RSAJWKSourceResolver;
import io.gravitee.policy.v3.jwt.processor.AbstractKeyProcessor;
import io.gravitee.policy.v3.jwt.processor.HMACKeyProcessor;
import io.gravitee.policy.v3.jwt.processor.JWKSKeyProcessor;
import io.gravitee.policy.v3.jwt.processor.NoAlgorithmRSAKeyProcessor;
import io.gravitee.policy.v3.jwt.processor.RSAKeyProcessor;
import io.gravitee.policy.v3.jwt.resolver.GatewaySignatureKeyResolver;
import io.gravitee.policy.v3.jwt.resolver.KeyResolver;
import io.gravitee.policy.v3.jwt.resolver.SignatureKeyResolver;
import io.gravitee.policy.v3.jwt.resolver.TemplatableSignatureKeyResolver;
import io.gravitee.policy.v3.jwt.resolver.UserDefinedSignatureKeyResolver;
import io.vertx.core.Vertx;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.net.ssl.SSLSession;
import org.checkerframework.checker.units.qual.C;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.env.Environment;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicyV3 {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTPolicyV3.class);

    public static final String CONTEXT_ATTRIBUTE_PREFIX = "jwt.";
    public static final String CONTEXT_ATTRIBUTE_JWT_CLAIMS = CONTEXT_ATTRIBUTE_PREFIX + "claims";
    public static final String CONTEXT_ATTRIBUTE_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "token";
    public static final String CONTEXT_ATTRIBUTE_CLIENT_ID = "client_id";
    public static final String CONTEXT_ATTRIBUTE_AUDIENCE = "aud";
    public static final String CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY = "azp";

    public static final String CONTEXT_ATTRIBUTE_OAUTH_PREFIX = "oauth.";
    public static final String CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID = CONTEXT_ATTRIBUTE_OAUTH_PREFIX + CONTEXT_ATTRIBUTE_CLIENT_ID;

    public static final String UNAUTHORIZED_MESSAGE = "Unauthorized";

    public static final String JWT_MISSING_TOKEN_KEY = "JWT_MISSING_TOKEN";
    public static final String JWT_INVALID_TOKEN_KEY = "JWT_INVALID_TOKEN";
    public static final String JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT = "JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT";
    public static final String CLAIMS_CNF = "cnf";
    public static final String CLAIMS_CNF_X5T = "x5t#S256";

    /**
     * Error message format
     */
    static final String errorMessageFormat = "[api-id:%s] [request-id:%s] [request-path:%s] %s";

    /**
     * The associated configuration to this JWT Policy
     */
    protected JWTPolicyConfiguration configuration;

    /**
     * Create a new JWT Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new JWT Policy instance
     */
    public JWTPolicyV3(JWTPolicyConfiguration configuration) {
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
                    final String api = String.valueOf(executionContext.getAttribute(ATTR_API));
                    MDC.put("api", api);
                    if (throwable != null) {
                        String key = JWT_INVALID_TOKEN_KEY;
                        if (throwable.getCause() instanceof InvalidTokenException) {
                            LOGGER.debug(
                                String.format(errorMessageFormat, api, request.id(), request.path(), throwable.getMessage()),
                                throwable.getCause()
                            );
                            request.metrics().setMessage(throwable.getCause().getCause().getMessage());
                        } else if (throwable instanceof InvalidCertificateThumbprintException) {
                            key = JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT;
                            LOGGER.debug(
                                String.format(errorMessageFormat, api, request.id(), request.path(), throwable.getMessage()),
                                throwable
                            );
                            request.metrics().setMessage(throwable.getCause().getCause().getMessage());
                        } else {
                            LOGGER.error(
                                String.format(errorMessageFormat, api, request.id(), request.path(), throwable.getMessage()),
                                throwable.getCause()
                            );
                            request
                                .metrics()
                                .setMessage(throwable.getCause() != null ? throwable.getCause().getMessage() : throwable.getMessage());
                        }
                        MDC.remove("api");
                        policyChain.failWith(PolicyResult.failure(key, HttpStatusCode.UNAUTHORIZED_401, UNAUTHORIZED_MESSAGE));
                    } else {
                        try {
                            // 3_ Set access_token in context
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_TOKEN, jwt);

                            String clientId = getClientId(claims);
                            executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, clientId);

                            final String user;
                            if (configuration.getUserClaim() != null && !configuration.getUserClaim().isEmpty()) {
                                user = (String) claims.getClaim(configuration.getUserClaim());
                            } else {
                                user = claims.getSubject();
                            }
                            executionContext.setAttribute(ATTR_USER, user);
                            request.metrics().setUser(user);

                            if (configuration.isExtractClaims()) {
                                executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
                            }

                            if (!configuration.isPropagateAuthHeader()) {
                                request.headers().remove(HttpHeaders.AUTHORIZATION);
                            }

                            // Finally continue the process...
                            policyChain.doNext(request, response);
                        } catch (Exception e) {
                            LOGGER.error(
                                String.format(errorMessageFormat, api, request.id(), request.path(), e.getMessage()),
                                e.getCause()
                            );
                            policyChain.failWith(
                                PolicyResult.failure(JWT_INVALID_TOKEN_KEY, HttpStatusCode.UNAUTHORIZED_401, UNAUTHORIZED_MESSAGE)
                            );
                        } finally {
                            MDC.remove("api");
                        }
                    }
                });
        } catch (Exception e) {
            MDC.put("api", String.valueOf(executionContext.getAttribute(ATTR_API)));
            LOGGER.error(
                String.format(errorMessageFormat, executionContext.getAttribute(ATTR_API), request.id(), request.path(), e.getMessage()),
                e.getCause()
            );
            MDC.remove("api");
            policyChain.failWith(PolicyResult.failure(JWT_MISSING_TOKEN_KEY, HttpStatusCode.UNAUTHORIZED_401, UNAUTHORIZED_MESSAGE));
        }
    }

    protected String getClientId(JWTClaimsSet claims) {
        if (!ObjectUtils.isEmpty(configuration.getClientIdClaim())) {
            Object clientIdClaim = claims.getClaim(configuration.getClientIdClaim());
            return extractClientId(clientIdClaim);
        }

        String clientId = null;

        // Look for the OAuth2 client_id of the Relying Party from the Authorized party claim
        String authorizedParty = (String) claims.getClaim(CONTEXT_ATTRIBUTE_AUTHORIZED_PARTY);
        if (authorizedParty != null && !authorizedParty.isEmpty()) {
            clientId = authorizedParty;
        }

        if (clientId == null) {
            // Look for the OAuth2 client_id of the Relying Party from the audience claim
            Object audClaim = claims.getClaim(CONTEXT_ATTRIBUTE_AUDIENCE);
            clientId = extractClientId(audClaim);
        }

        // Is there any client_id claim in JWT claims ?
        if (clientId == null) {
            clientId = (String) claims.getClaim(CONTEXT_ATTRIBUTE_CLIENT_ID);
        }

        return clientId;
    }

    protected String extractClientId(Object claim) {
        if (claim != null) {
            if (claim instanceof List) {
                List<String> claims = (List<String>) claim;
                // For the moment, we took only the first value of the array
                return claims.get(0);
            } else {
                return (String) claim;
            }
        }
        return null;
    }

    private CompletableFuture<JWTClaimsSet> validate(ExecutionContext executionContext, String token) throws Exception {
        try {
            final Signature signature = configuration.getSignature();

            AbstractKeyProcessor keyProcessor = null;

            if (configuration.getPublicKeyResolver() != KeyResolver.JWKS_URL) {
                SignatureKeyResolver signatureKeyResolver;
                switch (configuration.getPublicKeyResolver()) {
                    case GIVEN_KEY:
                        signatureKeyResolver =
                            new TemplatableSignatureKeyResolver(
                                executionContext.getTemplateEngine(),
                                new UserDefinedSignatureKeyResolver(configuration.getResolverParameter())
                            );
                        break;
                    case GATEWAY_KEYS:
                        signatureKeyResolver = new GatewaySignatureKeyResolver(executionContext.getComponent(Environment.class), token);
                        break;
                    default:
                        throw new IllegalArgumentException("Unexpected signature key resolver");
                }

                if (signature != null) {
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
                    // For backward compatibility
                    keyProcessor = new NoAlgorithmRSAKeyProcessor();
                    keyProcessor.setJwkSourceResolver(new RSAJWKSourceResolver(signatureKeyResolver));
                }
            } else {
                keyProcessor = new JWKSKeyProcessor();
                keyProcessor.setJwkSourceResolver(
                    new URLJWKSourceResolver(
                        executionContext.getTemplateEngine(),
                        configuration.getResolverParameter(),
                        new VertxResourceRetriever(
                            executionContext.getComponent(Vertx.class),
                            executionContext.getComponent(Configuration.class),
                            RetrieveOptions
                                .builder()
                                .connectTimeout(configuration.getConnectTimeout())
                                .requestTimeout(configuration.getRequestTimeout())
                                .useSystemProxy(configuration.isUseSystemProxy())
                                .followRedirects(configuration.getFollowRedirects())
                                .build()
                        )
                    )
                );
            }

            CompletableFuture<JWTClaimsSet> process = keyProcessor.process(signature, token);
            return process.thenApply(jwtClaimsSet -> {
                // Validate confirmation method
                JWTPolicyConfiguration.ConfirmationMethodValidation confirmationMethodValidation =
                    configuration.getConfirmationMethodValidation();
                if (
                    confirmationMethodValidation != null &&
                    confirmationMethodValidation.getCertificateBoundThumbprint().isEnabled() &&
                    !isValidCertificateThumbprint(
                        jwtClaimsSet,
                        executionContext.request().sslSession(),
                        executionContext.request().headers(),
                        confirmationMethodValidation.isIgnoreMissing(),
                        confirmationMethodValidation.getCertificateBoundThumbprint()
                    )
                ) {
                    throw new InvalidCertificateThumbprintException("Confirmation method validation failed");
                }
                return jwtClaimsSet;
            });
        } catch (ParseException pe) {
            return CompletableFuture.failedFuture(new InvalidTokenException(pe));
        }
    }

    protected static boolean isValidCertificateThumbprint(
        final JWTClaimsSet jwtClaimsSet,
        final SSLSession sslSession,
        final io.gravitee.gateway.api.http.HttpHeaders headers,
        final boolean ignoreMissingCnf,
        final JWTPolicyConfiguration.CertificateBoundThumbprint certificateBoundThumbprint
    ) {
        try {
            String tokenThumbprint = Optional
                .ofNullable(jwtClaimsSet.getJSONObjectClaim(CLAIMS_CNF))
                .map(cnf -> cnf.get(CLAIMS_CNF_X5T))
                .map(Object::toString)
                .orElse(null);

            // Ignore empty configuration method
            if (!StringUtils.hasText(tokenThumbprint) && ignoreMissingCnf) {
                return true;
            } else if (!StringUtils.hasText(tokenThumbprint) && !ignoreMissingCnf) {
                return false;
            }

            // Compute client certificate thumbprint
            Optional<X509Certificate> clientCertificate;
            if (certificateBoundThumbprint.isExtractCertificateFromHeader()) {
                clientCertificate = CertificateUtils.extractCertificate(headers, certificateBoundThumbprint.getHeaderName());
            } else {
                clientCertificate = CertificateUtils.extractPeerCertificate(sslSession);
            }
            return clientCertificate
                .map(x509Certificate -> CertificateUtils.generateThumbprint(x509Certificate, "SHA-256"))
                .map(tokenThumbprint::equals)
                .orElse(false);
        } catch (ParseException e) {
            LOGGER.debug("Unable to valid certificate thumbprint", e);
            return false;
        }
    }
}
