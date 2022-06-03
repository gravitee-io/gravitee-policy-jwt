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
package io.gravitee.policy.jwt.jwk.provider;

import static io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider.RESOLVED_PARAMETER;

import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.reactive.api.context.RequestExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.source.JWKSUrlJWKSourceResolver;
import io.gravitee.policy.jwt.jwk.source.ResourceRetriever;
import io.gravitee.policy.jwt.jwk.source.VertxResourceRetriever;
import io.reactivex.Maybe;
import io.vertx.reactivex.core.Vertx;
import java.time.Duration;

/**
 * {@link JWTProcessorProvider} based on {@link io.gravitee.policy.v3.jwt.resolver.KeyResolver#JWKS_URL}.
 * This provider creates a {@link JWTProcessor} with the appropriate {@link JWSKeySelector}s containing the keys retrieved from a remote JWKS url.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
class JwksUrlJWTProcessorProvider implements JWTProcessorProvider {

    private static final Duration JWKS_REFRESH_INTERVAL = Duration.ofMinutes(5);

    private final JWTPolicyConfiguration configuration;
    private ResourceRetriever resourceRetriever;

    public JwksUrlJWTProcessorProvider(final JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * {@inheritDoc}
     * Creates the {@link JWTProcessor} with the JWKS url defined at the policy configuration level.
     * Note: JWKS is retrieved thanks to the {@link JWKSUrlJWKSourceResolver} which handle refresh internally.
     *
     * @see JWKSUrlJWKSourceResolver
     */
    @Override
    public Maybe<JWTProcessor<SecurityContext>> provide(RequestExecutionContext ctx) {
        return Maybe.defer(() -> buildJWTProcessor(ctx, ctx.getInternalAttribute(RESOLVED_PARAMETER)));
    }

    private Maybe<JWTProcessor<SecurityContext>> buildJWTProcessor(RequestExecutionContext ctx, String url) {
        // Create a source resolver to resolve the Json Web Keystore from an url.
        final JWKSUrlJWKSourceResolver<SecurityContext> sourceResolver = new JWKSUrlJWKSourceResolver<>(
            url,
            getResourceRetriever(ctx),
            JWKS_REFRESH_INTERVAL
        );

        // Create a selector with the given jwks source resolver so keys used to verify jwt signatures will be selected from there.
        final JWSKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(
            configuration.getSignature().getAlg(),
            sourceResolver
        );

        // Create a jwt processor with the given selector.
        final DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(selector);

        // Initialize the Json Web Keystore before returning the jwt processor.
        return sourceResolver.initialize().andThen(Maybe.just(jwtProcessor));
    }

    private ResourceRetriever getResourceRetriever(RequestExecutionContext ctx) {
        if (resourceRetriever == null) {
            resourceRetriever =
                new VertxResourceRetriever(
                    ctx.getComponent(Vertx.class),
                    ctx.getComponent(Configuration.class),
                    configuration.isUseSystemProxy()
                );
        }

        return resourceRetriever;
    }
}
