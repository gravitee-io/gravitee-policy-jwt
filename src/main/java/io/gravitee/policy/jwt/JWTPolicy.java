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

import static io.gravitee.common.http.HttpStatusCode.UNAUTHORIZED_401;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_API;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.reporter.api.http.SecurityType.JWT;

import com.nimbusds.jwt.JWTClaimsSet;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.jupiter.api.ExecutionFailure;
import io.gravitee.gateway.jupiter.api.context.Request;
import io.gravitee.gateway.jupiter.api.context.RequestExecutionContext;
import io.gravitee.gateway.jupiter.api.policy.SecurityPolicy;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider;
import io.gravitee.policy.jwt.jwk.provider.JWTProcessorProvider;
import io.gravitee.policy.jwt.utils.TokenExtractor;
import io.gravitee.policy.v3.jwt.JWTPolicyV3;
import io.gravitee.reporter.api.http.Metrics;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import io.vertx.reactivex.core.http.HttpHeaders;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicy extends JWTPolicyV3 implements SecurityPolicy {

    private static final Logger log = LoggerFactory.getLogger(JWTPolicy.class);
    public static final String CONTEXT_ATTRIBUTE_JWT = "jwt";
    public static final String OAUTH2_ERROR_ACCESS_DENIED = "access_denied";
    public static final String GATEWAY_OAUTH2_ACCESS_DENIED_KEY = "GATEWAY_OAUTH2_ACCESS_DENIED";
    private static final Single<Boolean> TRUE = Single.just(true);

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
    public Single<Boolean> support(RequestExecutionContext ctx) {
        final LazyJWT jwtToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT);
        if (jwtToken != null) {
            return TRUE;
        }

        final Optional<String> optToken = TokenExtractor.lookFor(ctx.request());
        optToken.ifPresent(token -> ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, new LazyJWT(token)));

        return Single.just(optToken.isPresent());
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
    public Completable onInvalidSubscription(RequestExecutionContext ctx) {
        return ctx.interruptWith(
            new ExecutionFailure(HttpStatusCode.UNAUTHORIZED_401).key(GATEWAY_OAUTH2_ACCESS_DENIED_KEY).message(OAUTH2_ERROR_ACCESS_DENIED)
        );
    }

    @Override
    public Completable onRequest(RequestExecutionContext ctx) {
        return extractToken(ctx)
            .flatMapSingle(jwt -> validateToken(ctx, jwt).doOnSuccess(claims -> setAuthContextInfos(ctx, jwt, claims)))
            .ignoreElement();
    }

    private void setAuthContextInfos(RequestExecutionContext ctx, LazyJWT jwt, JWTClaimsSet claims) {
        final Request request = ctx.request();

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
        final Metrics metrics = request.metrics();
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

    private Maybe<LazyJWT> extractToken(RequestExecutionContext ctx) {
        Optional<String> token = Optional.ofNullable(ctx.getInternalAttribute(CONTEXT_ATTRIBUTE_TOKEN));

        try {
            if (token.isEmpty()) {
                token = TokenExtractor.extract(ctx.request());

                if (token.isEmpty()) {
                    return interrupt401AsMaybe(ctx, JWT_MISSING_TOKEN_KEY);
                }
            }
            return Maybe.just(new LazyJWT(token.get()));
        } catch (TokenExtractor.AuthorizationSchemeException e) {
            return interrupt401AsMaybe(ctx, JWT_INVALID_TOKEN_KEY);
        }
    }

    private Single<JWTClaimsSet> validateToken(RequestExecutionContext ctx, LazyJWT jwt) {
        return jwtProcessorResolver
            .provide(ctx)
            .flatMapSingle(jwtProcessor -> {
                try {
                    return Single.just(jwtProcessor.process(jwt.getDelegate(), null));
                } catch (Throwable throwable) {
                    reportError(ctx, throwable);
                    return interrupt401AsSingle(ctx, JWT_INVALID_TOKEN_KEY);
                }
            });
    }

    private <T> Maybe<T> interrupt401AsMaybe(RequestExecutionContext ctx, String key) {
        return interrupt401(ctx, key).toMaybe();
    }

    private <T> Single<T> interrupt401AsSingle(RequestExecutionContext ctx, String key) {
        return interrupt401(ctx, key).<T>toMaybe().toSingle();
    }

    private Completable interrupt401(RequestExecutionContext ctx, String key) {
        return ctx.interruptWith(new ExecutionFailure(UNAUTHORIZED_401).key(key).message(UNAUTHORIZED_MESSAGE));
    }

    private void reportError(RequestExecutionContext ctx, Throwable throwable) {
        if (throwable != null) {
            final Request request = ctx.request();
            request.metrics().setMessage(throwable.getMessage());

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
}
