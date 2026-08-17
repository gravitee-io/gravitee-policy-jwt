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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.ContextAttributes;
import io.gravitee.gateway.reactive.api.context.InternalContextAttributes;
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
import io.gravitee.policy.jwt.utils.ClaimPathResolver;
import io.gravitee.policy.jwt.utils.TokenExtractor;
import io.gravitee.policy.processing.JWTClaimsSetValidator;
import io.gravitee.policy.v3.jwt.JWTPolicyV3;
import io.gravitee.reporter.api.v4.metric.Metrics;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import io.vertx.rxjava3.core.http.HttpHeaders;
import java.net.URI;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
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
    public static final String JWT_POLICY_ERROR_KEY = "JWT_POLICY_ERROR";
    public static final String JWT_INSUFFICIENT_SCOPE = "JWT_INSUFFICIENT_SCOPE";

    // Error messages for RuntimeExceptions
    static final String ERROR_MSG_JWT_REVOKED = "JWT token has been revoked";
    static final String ERROR_MSG_MISSING_TOKEN = "Missing JWT token";
    static final String ERROR_MSG_EMPTY_TOKEN = "Empty JWT token";
    static final String ERROR_MSG_INVALID_THUMBPRINT = "Invalid certificate bound thumbprint";
    static final String ERROR_MSG_INSUFFICIENT_SCOPE = "JWT token does not carry the required scopes";

    // RFC 9728 Protected Resource Metadata support
    private static final String API_TYPE_MCP_PROXY = "MCP_PROXY";
    private static final String WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
    private static final String BEARER_CHALLENGE = "Bearer";
    private static final ObjectMapper METADATA_MAPPER = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    private static final Pattern SCOPE_SEPARATOR = Pattern.compile("\\s+");
    private static final Pattern QUERY_OR_FRAGMENT = Pattern.compile("[?#]");
    private static final String CLAIM_SCOPE = "scope";
    private static final String CLAIM_SCP = "scp";

    /**
     * RFC 9728 OAuth 2.0 Protected Resource Metadata document.
     */
    private record ProtectedResourceMetadata(
        @JsonProperty("resource") String resource,
        @JsonProperty("authorization_servers") List<String> authorizationServers,
        @JsonProperty("scopes_supported") List<String> scopesSupported
    ) {}

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

    /**
     * MCP_PROXY APIs advertising protected resource metadata don't require a Gravitee subscription:
     * clients register themselves dynamically against the authorization server, so no subscription
     * can have been created ahead of time. Every other combination still requires a valid subscription,
     * which keeps existing deployments untouched.
     */
    @Override
    public boolean requireSubscription(BaseExecutionContext context) {
        boolean mcpProxy = API_TYPE_MCP_PROXY.equals(context.getInternalAttribute(InternalContextAttributes.ATTR_INTERNAL_API_TYPE));
        return !(mcpProxy && hasProtectedResourceMetadata());
    }

    /**
     * Emits the {@code WWW-Authenticate} challenge, unconditionally: answering with a challenge is what
     * bearer authentication mandates, not an operator preference. When protected resource metadata is
     * configured, a {@code resource_metadata} hint of the shape
     * {@code scheme://authority/.well-known/oauth-protected-resource<request-path>} is appended so clients
     * can discover how to authenticate, per RFC 9728; the hint is dropped when the original request URL is
     * unavailable or unparseable.
     * <p>
     * The security chain calls this from a single place: the {@code GATEWAY_PLAN_UNRESOLVABLE} 401 raised
     * when no plan could execute. The 401s this policy raises itself do not reach it, and deliberately so -
     * emitting the header from the policy's own interrupt paths leaks it onto responses another plan
     * ultimately authorized, which is what got APIM-13239 reverted.
     */
    @Override
    public Single<Boolean> wwwAuthenticate(final HttpPlainExecutionContext ctx) {
        String challenge = BEARER_CHALLENGE;

        if (hasProtectedResourceMetadata()) {
            URI uri = originalRequestUri(ctx);
            if (uri != null) {
                String resourceMetadata =
                    uri.getScheme() + "://" + uri.getRawAuthority() + WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH + uri.getRawPath();
                challenge += " resource_metadata=\"" + resourceMetadata + "\"";
            }
        }

        ctx.response().headers().set(HttpHeaderNames.WWW_AUTHENTICATE, challenge);
        return Single.just(true);
    }

    /**
     * Serves the RFC 9728 OAuth 2.0 Protected Resource Metadata document at
     * {@code /.well-known/oauth-protected-resource}, advertising the configured authorization servers
     * as the issuers that can mint valid tokens for this resource. Only active when
     * {@code protectedResourceMetadata.authorizationServers} is configured.
     */
    @Override
    public Single<Boolean> onWellKnown(final HttpPlainExecutionContext ctx) {
        if (!hasProtectedResourceMetadata() || !ctx.request().path().contains(WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH)) {
            return Single.just(false);
        }

        URI uri = originalRequestUri(ctx);
        if (uri == null) {
            return Single.just(false);
        }

        String protectedResourcePath = protectedResourcePath(uri.getRawPath());
        if (protectedResourcePath == null) {
            return Single.just(false);
        }

        ProtectedResourceMetadata metadata = new ProtectedResourceMetadata(
            uri.getScheme() + "://" + uri.getRawAuthority() + protectedResourcePath,
            authorizationServers(),
            configuration.getRequiredScopes()
        );

        try {
            String document = METADATA_MAPPER.writeValueAsString(metadata);
            ctx.response().headers().set(HttpHeaderNames.CONTENT_TYPE, MediaType.APPLICATION_JSON);
            ctx.response().body(Buffer.buffer(document));
            return Single.just(true);
        } catch (JsonProcessingException e) {
            log.error("Unable to serialize JWT protected resource metadata", e);
            return Single.just(false);
        }
    }

    /**
     * Resolves the resource this document describes from the request path, accepting both placements
     * RFC 9728 §3.1 defines and clients probe: the inserted form
     * {@code /.well-known/oauth-protected-resource/my-api} and the path-based form
     * {@code /my-api/.well-known/oauth-protected-resource}. Returns {@code null} when the path is neither.
     */
    private static String protectedResourcePath(String rawPath) {
        String resourcePath;
        if (rawPath.startsWith(WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH)) {
            resourcePath = rawPath.substring(WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH.length());
            if (!resourcePath.isEmpty() && !resourcePath.startsWith("/")) {
                return null;
            }
        } else if (rawPath.endsWith(WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH)) {
            resourcePath = rawPath.substring(0, rawPath.length() - WELL_KNOWN_OAUTH_PROTECTED_RESOURCE_PATH.length());
        } else {
            return null;
        }
        return resourcePath.isEmpty() ? "/" : resourcePath;
    }

    /**
     * The original request URL is the raw request target, so it holds characters {@link URI} rejects but the
     * HTTP server accepts. Callers only need scheme, authority and path - and a resource identifier must carry
     * neither query nor fragment - so both are dropped before parsing. Runs on every request: degrade, never throw.
     */
    private URI originalRequestUri(BaseExecutionContext ctx) {
        String originalUrl = ctx.getAttribute(ContextAttributes.ATTR_REQUEST_ORIGINAL_URL);
        if (originalUrl == null) {
            return null;
        }
        try {
            return URI.create(QUERY_OR_FRAGMENT.split(originalUrl, 2)[0]);
        } catch (IllegalArgumentException e) {
            log.debug("Unable to parse the original request URL as a URI: {}", originalUrl);
            return null;
        }
    }

    private boolean hasProtectedResourceMetadata() {
        return !authorizationServers().isEmpty();
    }

    /**
     * The configured issuers, blank entries dropped, so the same list gates the feature and lands in the
     * document - an empty issuer must not open the gate and then be advertised.
     */
    private List<String> authorizationServers() {
        JWTPolicyConfiguration.ProtectedResourceMetadataConfiguration metadata = configuration.getProtectedResourceMetadata();
        if (metadata == null || metadata.getAuthorizationServers() == null) {
            return List.of();
        }
        return metadata
            .getAuthorizationServers()
            .stream()
            .filter(server -> server != null && !server.isBlank())
            .toList();
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
        return fetchJWTToken(ctx).flatMap(jwt ->
            validateToken(ctx, jwt)
                .flatMap(claims -> validateScopes(ctx, claims))
                .doOnSuccess(claims -> setAuthContextInfos(ctx, jwt, claims))
        );
    }

    private Single<JWTClaimsSet> validateScopes(BaseExecutionContext ctx, JWTClaimsSet claims) {
        if (!configuration.isCheckRequiredScopes()) {
            return Single.just(claims);
        }

        if (hasRequiredScopes(extractScopes(claims), configuration.getRequiredScopes(), configuration.isModeStrict())) {
            return Single.just(claims);
        }

        return interruptUnauthorized(ctx, JWT_INSUFFICIENT_SCOPE, new RuntimeException(ERROR_MSG_INSUFFICIENT_SCOPE));
    }

    /**
     * Reads the scopes granted to the token, accepting both shapes authorization servers use: the
     * space-delimited {@code scope} string of RFC 9068 and the {@code scp} array.
     */
    private static Collection<String> extractScopes(JWTClaimsSet claims) {
        Collection<String> scopes = readScopeClaim(claims.getClaim(CLAIM_SCOPE));
        return scopes != null ? scopes : readScopeClaim(claims.getClaim(CLAIM_SCP));
    }

    private static Collection<String> readScopeClaim(Object claim) {
        if (claim instanceof String scope) {
            return scope.isBlank() ? null : List.of(SCOPE_SEPARATOR.split(scope.trim()));
        }
        if (claim instanceof Collection<?> collection) {
            return collection.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        return null;
    }

    /**
     * Mirrors {@code Oauth2PolicyV3.hasRequiredScopes} so both plans read the same way: strict mode
     * demands every configured scope, lenient mode demands at least one.
     */
    private static boolean hasRequiredScopes(Collection<String> tokenScopes, List<String> requiredScopes, boolean modeStrict) {
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            return true;
        }
        if (tokenScopes == null || tokenScopes.isEmpty()) {
            return false;
        }
        if (modeStrict) {
            return tokenScopes.containsAll(requiredScopes);
        }
        return tokenScopes.stream().anyMatch(requiredScopes::contains);
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
                return interruptUnauthorized(ctx, JWT_REVOKED, new RuntimeException(ERROR_MSG_JWT_REVOKED));
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
                // Handle errors from JWT processor resolution (e.g., JWKS URL resolution failures)
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
                    return interruptUnauthorized(ctx, JWT_INVALID_TOKEN_KEY, exception);
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
            user = (String) ClaimPathResolver.resolve(claims, configuration.getUserClaim());
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
            ExecutionFailure failure = new ExecutionFailure(UNAUTHORIZED_401).key(key).message(UNAUTHORIZED_MESSAGE);
            if (cause != null) {
                failure = failure.cause(cause);
            }
            return httpPlainExecutionContext.interruptWith(failure).<T>toMaybe().toSingle();
        }
        // FIXME: Kafka Gateway - manage interruption with Kafka.
        return Single.error(cause != null ? cause : new Exception(key));
    }

    private <T> Single<T> interruptInternalError(BaseExecutionContext ctx, String key, Throwable cause) {
        ExecutionFailure failure = new ExecutionFailure(INTERNAL_SERVER_ERROR_500)
            .key(key)
            .message(HttpResponseStatus.INTERNAL_SERVER_ERROR.reasonPhrase())
            .cause(cause);
        return interruptInternalError(ctx, failure);
    }

    private <T> Single<T> interruptInternalError(BaseExecutionContext ctx, ExecutionFailure failure) {
        if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
            return httpPlainExecutionContext.interruptWith(failure).<T>toMaybe().toSingle();
        }

        Throwable propagatedCause = Optional.ofNullable(failure.cause()).orElseGet(() -> new IllegalStateException(failure.key()));
        return Single.error(propagatedCause);
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
