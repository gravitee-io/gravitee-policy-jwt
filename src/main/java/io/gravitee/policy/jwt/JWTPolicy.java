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
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.gateway.reactive.api.policy.http.HttpSecurityPolicy;
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
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy extends JWTPolicyV3 implements HttpSecurityPolicy {

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
        LazyJWT jwtToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT);

        if (jwtToken == null) {
            jwtToken = TokenExtractor.extract(ctx.request()).map(LazyJWT::new).orElse(null);
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
        return handleSecurity(ctx);
    }

    private Completable handleSecurity(final HttpPlainExecutionContext ctx) {
        return extractToken(ctx)
            .flatMapSingle(jwt -> validateToken(ctx, jwt).doOnSuccess(claims -> setAuthContextInfos(ctx, jwt, claims)))
            .ignoreElement();
    }

    private void setAuthContextInfos(HttpPlainExecutionContext ctx, LazyJWT jwt, JWTClaimsSet claims) {
        final HttpPlainRequest request = ctx.request();

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

        if (!configuration.isPropagateAuthHeader()) {
            request.headers().remove(HttpHeaders.AUTHORIZATION);
        }
    }

    private Maybe<LazyJWT> extractToken(HttpPlainExecutionContext ctx) {
        Optional<String> token = TokenExtractor.extract(ctx.request());
        if (token.isEmpty()) {
            return interrupt401AsMaybe(ctx, JWT_MISSING_TOKEN_KEY);
        }
        String tokenValue = token.get();
        if (tokenValue.isEmpty()) {
            return interrupt401AsMaybe(ctx, JWT_INVALID_TOKEN_KEY);
        }
        return Maybe.just(new LazyJWT(token.get()));
    }

    private Single<JWTClaimsSet> validateToken(HttpPlainExecutionContext ctx, LazyJWT jwt) {
        return jwtProcessorResolver
            .provide(ctx)
            .flatMapSingle(jwtProcessor -> {
                JWTClaimsSet jwtClaimsSet;
                // Validate JWT
                try {
                    jwtClaimsSet = jwtProcessor.process(jwt.getDelegate(), null);
                } catch (Exception exception) {
                    reportError(ctx, exception);
                    return interrupt401AsSingle(ctx, JWT_INVALID_TOKEN_KEY);
                }

                // Validate confirmation method
                JWTPolicyConfiguration.ConfirmationMethodValidation confirmationMethodValidation =
                    configuration.getConfirmationMethodValidation();
                if (confirmationMethodValidation != null && confirmationMethodValidation.getCertificateBoundThumbprint().isEnabled()) {
                    if (
                        !isValidCertificateThumbprint(
                            jwtClaimsSet,
                            ctx.request().tlsSession(),
                            ctx.request().headers(),
                            confirmationMethodValidation.isIgnoreMissing(),
                            confirmationMethodValidation.getCertificateBoundThumbprint()
                        )
                    ) {
                        return interrupt401AsSingle(ctx, JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT);
                    }
                }
                return Single.just(jwtClaimsSet);
            })
            .toSingle();
    }

    private <T> Maybe<T> interrupt401AsMaybe(HttpPlainExecutionContext ctx, String key) {
        return interrupt401(ctx, key).toMaybe();
    }

    private <T> Single<T> interrupt401AsSingle(HttpPlainExecutionContext ctx, String key) {
        return interrupt401(ctx, key).<T>toMaybe().toSingle();
    }

    private Completable interrupt401(HttpPlainExecutionContext ctx, String key) {
        return ctx.interruptWith(new ExecutionFailure(UNAUTHORIZED_401).key(key).message(UNAUTHORIZED_MESSAGE));
    }

    private void reportError(HttpPlainExecutionContext ctx, Throwable throwable) {
        if (throwable != null) {
            final HttpPlainRequest request = ctx.request();
            ctx.metrics().setErrorMessage(throwable.getMessage());

            if (log.isDebugEnabled()) {
                try {
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
}
