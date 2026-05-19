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

import static io.gravitee.common.http.HttpStatusCode.INTERNAL_SERVER_ERROR_500;
import static io.gravitee.common.http.HttpStatusCode.UNAUTHORIZED_401;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.reporter.api.http.SecurityType.JWT;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.context.kafka.KafkaConnectionContext;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.gateway.reactive.api.policy.http.HttpSecurityPolicy;
import io.gravitee.gateway.reactive.api.policy.kafka.KafkaSecurityPolicy;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider;
import io.gravitee.policy.jwt.jwk.provider.JWTProcessorProvider;
import io.gravitee.policy.jwt.jwk.source.JWKSUrlJWKSourceResolver;
import io.gravitee.policy.jwt.revocation.RevocationChecker;
import io.gravitee.policy.jwt.revocation.RevocationCheckerFactory;
import io.gravitee.policy.jwt.utils.TokenExtractor;
import io.gravitee.policy.processing.JWTClaimsSetValidator;
import io.gravitee.policy.v3.jwt.JWTPolicyV3;
import io.gravitee.reporter.api.v4.metric.Metrics;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.http.HttpHeaders;
import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import javax.security.auth.callback.Callback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.env.Environment;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy extends JWTPolicyV3 implements HttpSecurityPolicy, KafkaSecurityPolicy {

    public static final String CONTEXT_ATTRIBUTE_JWT = "jwt";

    private static final String KAFKA_OAUTHBEARER_MAX_TOKEN_LIFETIME = "kafka.oauthbearer.maxTokenLifetime";
    private static final long DEFAULT_MAX_TOKEN_LIFETIME_MS = 60 * 60 * 1000L; // 1 hour
    public static final String JWT_REVOKED = "JWT_REVOKED";
    public static final String JWT_INVALID_CLIENT_ID_KEY = "JWT_INVALID_CLIENT_ID";
    public static final String JWT_UNAUTHORIZED_CLIENT_ID_KEY = "JWT_UNAUTHORIZED_CLIENT_ID";
    public static final String JWT_INVALID_CLAIMS_KEY = "JWT_INVALID_CLAIMS";
    public static final String JWT_EXPIRED_TOKEN_KEY = "JWT_EXPIRED_TOKEN";
    public static final String JWT_POLICY_ERROR_KEY = "JWT_POLICY_ERROR";
    /**
     * Message of {@link com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier#EXPIRED_JWT_EXCEPTION}.
     */
    private static final String EXPIRED_JWT_EXCEPTION_MESSAGE = "Expired JWT";

    static final String ERROR_MSG_MISSING_TOKEN = "Missing JWT token";
    static final String ERROR_MSG_EMPTY_TOKEN = "Empty JWT token";
    static final String ERROR_MSG_INVALID_THUMBPRINT = "Invalid certificate bound thumbprint";

    private static final Logger log = LoggerFactory.getLogger(JWTPolicy.class);

    private final JWTProcessorProvider jwtProcessorResolver;

    private RevocationChecker revocationChecker;
    private JWTClaimsSetValidator jwtClaimsSetValidator;

    public JWTPolicy(JWTPolicyConfiguration configuration) {
        super(configuration);
        this.jwtProcessorResolver = new DefaultJWTProcessorProvider(configuration);
    }

    @Override
    public String id() {
        return "jwt";
    }

    /**
     * Order set to 0 to make sure it will be executed before all other security policies.
     *
     * @return 0
     */
    @Override
    public int order() {
        return 0;
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(HttpPlainExecutionContext ctx) {
        return getSecurityTokenFromContext(ctx);
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(KafkaConnectionContext ctx) {
        return getSecurityTokenFromContext(ctx);
    }

    /**
     * {@inheritDoc}
     * Let the gateway validate the subscription the <code>clientId</code> in case of succeeded authentication.
     *
     * @return <code>true</code>, indicating that the subscription must be validated once the authentication has been successfully done.
     */
    @Override
    public boolean requireSubscription() {
        return true;
    }

    @Override
    public Completable onRequest(HttpPlainExecutionContext ctx) {
        return handleSecurity(ctx).flatMapCompletable(jwtClaimsSet ->
            Completable.fromRunnable(() -> {
                Metrics metrics = ctx.metrics();
                metrics.setUser(ctx.getAttribute(ATTR_USER));
                metrics.setSecurityType(JWT);
                metrics.setSecurityToken(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID));

                if (!configuration.isPropagateAuthHeader()) {
                    ctx.request().headers().remove(HttpHeaders.AUTHORIZATION);
                }

                ctx.response().headers().remove("WWW-Authenticate");
            })
        );
    }

    /**
     * Invoked by the gateway security chain when no plan could handle the request (e.g. missing token or invalid
     * client_id during plan resolution). Sets {@code WWW-Authenticate} for JWT-related failures that occur before
     * {@link #onRequest(HttpPlainExecutionContext)}.
     *
     * @return {@code true} if the header was set, {@code false} otherwise so another security policy may contribute.
     */
    @Override
    public Single<Boolean> wwwAuthenticate(HttpPlainExecutionContext ctx) {
        return Single.fromCallable(() -> {
            Optional<String> token = TokenExtractor.extract(ctx);
            if (token.isEmpty()) {
                addWwwAuthenticateHeader(ctx, JWT_MISSING_TOKEN_KEY);
                return true;
            }
            String tokenValue = token.get();
            if (tokenValue.isEmpty()) {
                addWwwAuthenticateHeader(ctx, JWT_INVALID_TOKEN_KEY);
                return true;
            }
            ClientIdExtractionResult extractionResult = extractClientId(new LazyJWT(tokenValue));
            if (extractionResult.clientId() == null && extractionResult.errorKey() != null) {
                addWwwAuthenticateHeader(ctx, extractionResult.errorKey());
                return true;
            }
            return false;
        });
    }

    @Override
    public Completable authenticate(KafkaConnectionContext ctx) {
        return handleSecurity(ctx)
            .flatMapCompletable(jwtClaimsSet ->
                Completable.fromRunnable(() -> {
                    Callback[] callbacks = ctx.callbacks();
                    for (Callback callback : callbacks) {
                        if (callback instanceof OAuthBearerValidatorCallback oauthCallback) {
                            String extractedToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_TOKEN);
                            String user = ctx.getAttribute(ATTR_USER);
                            Date expirationTime = jwtClaimsSet.getExpirationTime();
                            Date issueTime = jwtClaimsSet.getIssueTime();

                            Environment environment = ctx.getComponent(Environment.class);
                            long maxTokenLifetime =
                                System.currentTimeMillis() +
                                environment.getProperty(KAFKA_OAUTHBEARER_MAX_TOKEN_LIFETIME, Long.class, DEFAULT_MAX_TOKEN_LIFETIME_MS);

                            OAuthBearerToken token = new BasicOAuthBearerToken(
                                extractedToken,
                                Set.of(), // Scopes are fully managed by Gravitee, it is useless to extract & provide them to the Kafka security context.
                                (expirationTime == null ? maxTokenLifetime : Math.min(maxTokenLifetime, expirationTime.getTime())),
                                user != null ? user : "unknown",
                                (issueTime == null ? null : issueTime.getTime())
                            );

                            oauthCallback.token(token);
                        }
                    }
                })
            )
            .onErrorResumeNext(throwable -> {
                Callback[] callbacks = ctx.callbacks();
                for (Callback callback : callbacks) {
                    if (callback instanceof OAuthBearerValidatorCallback oauthCallback) {
                        oauthCallback.error("invalid_token", null, null);
                    }
                }

                return Completable.complete();
            });
    }

    private Maybe<SecurityToken> getSecurityTokenFromContext(BaseExecutionContext ctx) {
        LazyJWT jwtToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT);

        if (jwtToken == null) {
            jwtToken = TokenExtractor.extract(ctx).map(LazyJWT::new).orElse(null);
        }

        if (jwtToken != null) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, jwtToken);
            ClientIdExtractionResult extractionResult = extractClientId(jwtToken);
            if (extractionResult.clientId() != null) {
                return Maybe.just(SecurityToken.forClientId(extractionResult.clientId()));
            }
            return Maybe.just(SecurityToken.invalid(SecurityToken.TokenType.CLIENT_ID));
        }

        return Maybe.empty();
    }

    private ClientIdExtractionResult extractClientId(LazyJWT jwtToken) {
        try {
            JWT jwt = jwtToken.getDelegate();
            if (jwt != null) {
                String clientId = getClientId(jwt.getJWTClaimsSet());
                if (clientId != null) {
                    return ClientIdExtractionResult.success(clientId);
                }
                return ClientIdExtractionResult.error(JWT_INVALID_CLIENT_ID_KEY);
            }
            return ClientIdExtractionResult.error(JWT_INVALID_TOKEN_KEY);
        } catch (ParseException e) {
            log.error("Failed to parse JWT claim set while looking for clientId", e);
            return ClientIdExtractionResult.error(JWT_INVALID_TOKEN_KEY);
        } catch (Exception e) {
            log.error("Failed to extract clientId from JWT claim set", e);
            return ClientIdExtractionResult.error(JWT_INVALID_TOKEN_KEY);
        }
    }

    private record ClientIdExtractionResult(String clientId, String errorKey) {
        private static ClientIdExtractionResult success(String clientId) {
            return new ClientIdExtractionResult(clientId, null);
        }

        private static ClientIdExtractionResult error(String errorKey) {
            return new ClientIdExtractionResult(null, errorKey);
        }
    }

    private Single<JWTClaimsSet> handleSecurity(final BaseExecutionContext ctx) {
        return fetchJWTToken(ctx).flatMap(jwt -> validateToken(ctx, jwt).doOnSuccess(claims -> setAuthContextInfos(ctx, jwt, claims)));
    }

    private Single<LazyJWT> fetchJWTToken(BaseExecutionContext ctx) {
        Optional<String> token = TokenExtractor.extract(ctx);
        if (token.isEmpty()) {
            return interruptUnauthorized(ctx, JWT_MISSING_TOKEN_KEY, new RuntimeException(ERROR_MSG_MISSING_TOKEN));
        }
        String tokenValue = token.get();
        if (tokenValue.isEmpty()) {
            return interruptUnauthorized(ctx, JWT_INVALID_TOKEN_KEY, new RuntimeException(ERROR_MSG_EMPTY_TOKEN));
        }
        return Single.just(new LazyJWT(token.get()));
    }

    private Single<JWTClaimsSet> validateRevocation(BaseExecutionContext ctx, JWTClaimsSet claims) {
        if (this.configuration.getRevocationCheck() == null || !this.configuration.getRevocationCheck().isEnabled()) {
            return Single.just(claims);
        }

        try {
            if (this.revocationChecker == null) {
                this.revocationChecker = RevocationCheckerFactory.create(this.configuration.getRevocationCheck(), ctx);
            }

            if (this.revocationChecker.isRevoked(claims)) {
                return interruptUnauthorized(ctx, JWT_REVOKED);
            }

            return Single.just(claims);
        } catch (Exception e) {
            log.warn("Error during revocation check, skipping revocation check", e);
            return Single.just(claims);
        }
    }

    private Single<JWTClaimsSet> validateToken(BaseExecutionContext ctx, LazyJWT jwt) {
        return jwtProcessorResolver
            .provide(ctx)
            .onErrorResumeNext(throwable -> {
                reportError(ctx, throwable);
                if (throwable instanceof JWKSUrlJWKSourceResolver.ResolutionException resolutionException) {
                    return this.<JWTProcessor<SecurityContext>>interruptInternalError(ctx, resolutionException.failure()).toMaybe();
                }
                return this.<JWTProcessor<SecurityContext>>interruptInternalError(ctx, JWT_POLICY_ERROR_KEY, throwable).toMaybe();
            })
            .flatMapSingle(jwtProcessor -> {
                JWTClaimsSet jwtClaimsSet;
                // Validate JWT
                try {
                    jwtClaimsSet = extractJwtClaimsSet(ctx, jwt, jwtProcessor);
                } catch (Exception exception) {
                    reportError(ctx, exception);
                    return interruptUnauthorized(ctx, resolveUnauthorizedKey(exception));
                }

                return validateRevocation(ctx, jwtClaimsSet).flatMap(claims -> {
                    // FIXME: Kafka Gateway - https://gravitee.atlassian.net/browse/APIM-7523
                    if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
                        // Validate confirmation method
                        JWTPolicyConfiguration.ConfirmationMethodValidation confirmationMethodValidation =
                            configuration.getConfirmationMethodValidation();
                        if (
                            confirmationMethodValidation != null && confirmationMethodValidation.getCertificateBoundThumbprint().isEnabled()
                        ) {
                            if (
                                !isValidCertificateThumbprint(
                                    claims,
                                    httpPlainExecutionContext.request().tlsSession(),
                                    httpPlainExecutionContext.request().headers(),
                                    confirmationMethodValidation.isIgnoreMissing(),
                                    confirmationMethodValidation.getCertificateBoundThumbprint()
                                )
                            ) {
                                jwtClaimsSetValidator.invalidate(jwt);
                                return interruptUnauthorized(
                                    httpPlainExecutionContext,
                                    JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT,
                                    new RuntimeException(ERROR_MSG_INVALID_THUMBPRINT)
                                );
                            }
                        }
                    }
                    return Single.just(claims);
                });
            })
            .toSingle();
    }

    private JWTClaimsSet extractJwtClaimsSet(BaseExecutionContext ctx, LazyJWT jwt, JWTProcessor<SecurityContext> jwtProcessor)
        throws BadJOSEException, JOSEException {
        if (this.jwtClaimsSetValidator == null) {
            this.jwtClaimsSetValidator = JWTClaimsSetValidator.create(ctx);
        }

        return jwtClaimsSetValidator.extract(jwtProcessor, jwt);
    }

    private void setAuthContextInfos(BaseExecutionContext ctx, LazyJWT jwt, JWTClaimsSet claims) {
        // 3_ Set access_token in context
        ctx.setAttribute(CONTEXT_ATTRIBUTE_TOKEN, jwt.getToken());

        String clientId = getClientId(claims);
        ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_CLIENT_ID, clientId);

        final String user;
        if (configuration.getUserClaim() != null && !configuration.getUserClaim().isEmpty()) {
            user = (String) claims.getClaim(configuration.getUserClaim());
        } else {
            user = claims.getSubject();
        }
        ctx.setAttribute(ATTR_USER, user);

        if (configuration.isExtractClaims()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
        }
    }

    private <T> Single<T> interruptUnauthorized(BaseExecutionContext ctx, String key, Throwable cause) {
        if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
            addWwwAuthenticateHeader(httpPlainExecutionContext, key);
            ExecutionFailure failure = new ExecutionFailure(UNAUTHORIZED_401).key(key).message(UNAUTHORIZED_MESSAGE);
            if (cause != null) {
                failure = failure.cause(cause);
            }
            return httpPlainExecutionContext.interruptWith(failure).<T>toMaybe().toSingle();
        }
        // FIXME: Kafka Gateway - manage interruption with Kafka.
        return Single.error(cause != null ? cause : new Exception(key));
    }

    private <T> Single<T> interruptUnauthorized(BaseExecutionContext ctx, String key) {
        return interruptUnauthorized(ctx, key, null);
    }

    private <T> Single<T> interruptInternalError(BaseExecutionContext ctx, String key, Throwable cause) {
        ExecutionFailure failure = new ExecutionFailure(INTERNAL_SERVER_ERROR_500)
            .key(key)
            .message(HttpResponseStatus.INTERNAL_SERVER_ERROR.reasonPhrase())
            .cause(cause);
        return interruptInternalError(ctx, failure);
    }

    private <T> Single<T> interruptInternalError(BaseExecutionContext ctx, ExecutionFailure failure) {
        String failureKey = Optional.ofNullable(failure.key()).orElse(JWT_POLICY_ERROR_KEY);
        String failureMessage = Optional.ofNullable(failure.message()).orElse(HttpResponseStatus.INTERNAL_SERVER_ERROR.reasonPhrase());
        ExecutionFailure safeFailure = new ExecutionFailure(INTERNAL_SERVER_ERROR_500)
            .key(failureKey)
            .message(failureMessage)
            .cause(failure.cause());

        if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
            return httpPlainExecutionContext.interruptWith(safeFailure).<T>toMaybe().toSingle();
        }

        Throwable propagatedCause = Optional.ofNullable(safeFailure.cause()).orElseGet(() -> new IllegalStateException(failureKey));
        return Single.error(propagatedCause);
    }

    private void addWwwAuthenticateHeader(HttpPlainExecutionContext ctx, String key) {
        String realm = Optional.ofNullable(configuration.getRealm())
            .filter(r -> !r.isBlank())
            .orElse("api-gateway");

        StringJoiner headerValue = new StringJoiner(", ");
        headerValue.add("Bearer realm=\"" + realm + "\"");
        headerValue.add("error=\"" + (JWT_MISSING_TOKEN_KEY.equals(key) ? "invalid_request" : "invalid_token") + "\"");
        headerValue.add("error_description=\"" + resolveErrorDescription(key) + "\"");

        ctx.response().headers().set("WWW-Authenticate", headerValue.toString());
    }

    private static String resolveErrorDescription(String key) {
        return switch (key) {
            case JWT_MISSING_TOKEN_KEY -> "No access token was provided";
            case JWT_REVOKED -> "The access token has been revoked";
            case JWT_INVALID_CLIENT_ID_KEY -> "The access token does not contain a valid client_id claim";
            case JWT_UNAUTHORIZED_CLIENT_ID_KEY -> "The access token client_id is not authorized";
            case JWT_EXPIRED_TOKEN_KEY -> "The access token is expired";
            case JWT_INVALID_CLAIMS_KEY -> "The access token claims are invalid";
            case JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT -> "The access token certificate-bound thumbprint is invalid";
            default -> "The access token is invalid";
        };
    }

    private static String resolveUnauthorizedKey(Throwable throwable) {
        if (throwable instanceof BadJWTException badJwtException && isExpiredJwt(badJwtException)) {
            return JWT_EXPIRED_TOKEN_KEY;
        }
        if (throwable instanceof BadJWTException) {
            return JWT_INVALID_CLAIMS_KEY;
        }
        return JWT_INVALID_TOKEN_KEY;
    }

    private static boolean isExpiredJwt(BadJWTException badJwtException) {
        return EXPIRED_JWT_EXCEPTION_MESSAGE.equals(badJwtException.getMessage());
    }

    private void reportError(BaseExecutionContext ctx, Throwable throwable) {
        if (throwable != null) {
            if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
                httpPlainExecutionContext.metrics().setErrorMessage(throwable.getMessage());

                if (log.isDebugEnabled()) {
                    try {
                        final HttpPlainRequest request = httpPlainExecutionContext.request();
                        final String api = httpPlainExecutionContext.getAttribute(ATTR_API);
                        MDC.put("api", api);

                        log.debug(
                            "[api-id:{}] [request-id:{}] [request-path:{}] {}",
                            api,
                            request.id(),
                            request.path(),
                            throwable.getMessage(),
                            throwable
                        );
                    } finally {
                        MDC.remove("api");
                    }
                }
            }
        }
    }
}
