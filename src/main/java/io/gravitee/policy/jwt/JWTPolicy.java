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

import static io.gravitee.common.http.HttpStatusCode.UNAUTHORIZED_401;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.reporter.api.http.SecurityType.JWT;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
import io.gravitee.policy.jwt.utils.TokenExtractor;
import io.gravitee.policy.v3.jwt.JWTPolicyV3;
import io.gravitee.reporter.api.v4.metric.Metrics;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.http.HttpHeaders;
import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.callback.Callback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy extends JWTPolicyV3 implements HttpSecurityPolicy, KafkaSecurityPolicy {

    public static final String CONTEXT_ATTRIBUTE_JWT = "jwt";
    private static final Logger log = LoggerFactory.getLogger(JWTPolicy.class);

    private final JWTProcessorProvider jwtProcessorResolver;

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
        return handleSecurity(ctx)
            .flatMapCompletable(jwtClaimsSet ->
                Completable.fromRunnable(() -> {
                    if (!configuration.isPropagateAuthHeader()) {
                        ctx.request().headers().remove(HttpHeaders.AUTHORIZATION);
                    }
                })
            );
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

                            OAuthBearerToken token = new BasicOAuthBearerToken(
                                extractedToken,
                                Set.of(), // Scopes are fully managed by Gravitee, it is useless to extract & provide them to the Kafka security context.
                                (expirationTime == null ? Long.MAX_VALUE : expirationTime.getTime()),
                                user,
                                (issueTime == null ? null : issueTime.getTime())
                            );

                            oauthCallback.token(token);
                        }
                    }
                })
            );
    }

    private Maybe<SecurityToken> getSecurityTokenFromContext(BaseExecutionContext ctx) {
        LazyJWT jwtToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT);

        if (jwtToken == null) {
            jwtToken = TokenExtractor.extract(ctx).map(LazyJWT::new).orElse(null);
        }

        if (jwtToken != null) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, jwtToken);
            String clientId = getClientId(jwtToken);
            if (clientId != null) {
                return Maybe.just(SecurityToken.forClientId(clientId));
            }
            return Maybe.just(SecurityToken.invalid(SecurityToken.TokenType.CLIENT_ID));
        }

        return Maybe.empty();
    }

    private String getClientId(LazyJWT jwtToken) {
        try {
            JWT jwt = jwtToken.getDelegate();
            if (jwt != null) {
                return getClientId(jwt.getJWTClaimsSet());
            }
        } catch (ParseException e) {
            log.error("Failed to parse JWT claim set while looking for clientId", e);
        }
        return null;
    }

    private Single<JWTClaimsSet> handleSecurity(final BaseExecutionContext ctx) {
        return fetchJWTToken(ctx).flatMap(jwt -> validateToken(ctx, jwt).doOnSuccess(claims -> setAuthContextInfos(ctx, jwt, claims)));
    }

    private Single<LazyJWT> fetchJWTToken(BaseExecutionContext ctx) {
        Optional<String> token = TokenExtractor.extract(ctx);
        if (token.isEmpty()) {
            return interruptUnauthorized(ctx, JWT_MISSING_TOKEN_KEY);
        }
        String tokenValue = token.get();
        if (tokenValue.isEmpty()) {
            return interruptUnauthorized(ctx, JWT_INVALID_TOKEN_KEY);
        }
        return Single.just(new LazyJWT(token.get()));
    }

    private Single<JWTClaimsSet> validateToken(BaseExecutionContext ctx, LazyJWT jwt) {
        return jwtProcessorResolver
            .provide(ctx)
            .flatMapSingle(jwtProcessor -> {
                JWTClaimsSet jwtClaimsSet;
                // Validate JWT
                try {
                    jwtClaimsSet = jwtProcessor.process(jwt.getDelegate(), null);
                } catch (Exception exception) {
                    reportError(ctx, exception);
                    return interruptUnauthorized(ctx, JWT_INVALID_TOKEN_KEY);
                }

                // FIXME: Kafka Gateway - https://gravitee.atlassian.net/browse/APIM-7523
                if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
                    // Validate confirmation method
                    JWTPolicyConfiguration.ConfirmationMethodValidation confirmationMethodValidation =
                        configuration.getConfirmationMethodValidation();
                    if (confirmationMethodValidation != null && confirmationMethodValidation.getCertificateBoundThumbprint().isEnabled()) {
                        if (
                            !isValidCertificateThumbprint(
                                jwtClaimsSet,
                                httpPlainExecutionContext.request().tlsSession(),
                                httpPlainExecutionContext.request().headers(),
                                confirmationMethodValidation.isIgnoreMissing(),
                                confirmationMethodValidation.getCertificateBoundThumbprint()
                            )
                        ) {
                            return interruptUnauthorized(httpPlainExecutionContext, JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT);
                        }
                    }
                }
                return Single.just(jwtClaimsSet);
            })
            .toSingle();
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
        Metrics metrics = ctx.metrics();
        metrics.setUser(user);
        metrics.setSecurityType(JWT);
        metrics.setSecurityToken(clientId);

        if (configuration.isExtractClaims()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT_CLAIMS, claims.getClaims());
        }
    }

    private <T> Single<T> interruptUnauthorized(BaseExecutionContext ctx, String key) {
        if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
            return httpPlainExecutionContext
                .interruptWith(new ExecutionFailure(UNAUTHORIZED_401).key(key).message(UNAUTHORIZED_MESSAGE))
                .<T>toMaybe()
                .toSingle();
        }
        // FIXME: Kafka Gateway - manage interruption with Kafka.
        return Single.error(new Exception(key));
    }

    private void reportError(BaseExecutionContext ctx, Throwable throwable) {
        if (throwable != null) {
            ctx.metrics().setErrorMessage(throwable.getMessage());

            if (log.isDebugEnabled()) {
                if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
                    try {
                        final HttpPlainRequest request = httpPlainExecutionContext.request();
                        final String api = ctx.getAttribute(ATTR_API);
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
