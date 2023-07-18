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
package io.gravitee.policy.jwt.jwk.provider;

import static io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider.ATTR_INTERNAL_RESOLVED_PARAMETER;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.selector.NoKidJWSVerificationKeySelector;
import io.gravitee.policy.jwt.utils.JWKBuilder;
import io.reactivex.rxjava3.core.Maybe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link JWTProcessorProvider} based on {@link io.gravitee.policy.v3.jwt.resolver.KeyResolver#GIVEN_KEY}.
 * This provider creates a {@link JWTProcessor} with the appropriate {@link JWSKeySelector}s containing only the given key.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
class GivenKeyJWTProcessorProvider implements JWTProcessorProvider {

    private static final Logger log = LoggerFactory.getLogger(GivenKeyJWTProcessorProvider.class);

    private final JWTPolicyConfiguration configuration;

    public GivenKeyJWTProcessorProvider(final JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * {@inheritDoc}
     * Creates the {@link JWTProcessor} with the given key defined at the policy configuration level and cache it for reuse.
     */
    @Override
    public Maybe<JWTProcessor<SecurityContext>> provide(HttpExecutionContext ctx) {
        return Maybe.fromCallable(() -> buildJWTProcessor(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)));
    }

    private JWTProcessor<SecurityContext> buildJWTProcessor(String keyValue) {
        final DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        try {
            // Explicitly use a NoKidJWSVerificationKeySelector as the given key does not have keyId and nimbus library always try to match incoming jwt kid with the jwk kid.
            final JWSKeySelector<SecurityContext> selector = new NoKidJWSVerificationKeySelector<>(
                configuration.getSignature().getAlg(),
                new ImmutableJWKSet<>(new JWKSet(JWKBuilder.buildKey(null, keyValue, configuration.getSignature().getAlg())))
            );

            jwtProcessor.setJWSKeySelector(selector);
        } catch (Throwable throwable) {
            log.warn("Error occurred when loading key. Key will be ignored.", throwable);
        }

        return jwtProcessor;
    }
}
