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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.reactive.api.context.HttpExecutionContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.v3.jwt.resolver.KeyResolver;
import io.reactivex.rxjava3.core.Maybe;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default processor provider that can be used by the policy to select the right {@link JWTProcessor}
 * Internally, relies on different {@link JWTProcessorProvider} and act as a cache to avoid useless recreation and allow subsequent reuse.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class DefaultJWTProcessorProvider implements JWTProcessorProvider {

    static final String ATTR_INTERNAL_RESOLVED_PARAMETER = "resolvedParameter";

    private final String resolverParameter;
    private final Map<String, JWTProcessor<SecurityContext>> jwtProcessors;
    private final JWTProcessorProvider jwtProcessorProvider;

    public DefaultJWTProcessorProvider(final JWTPolicyConfiguration configuration) {
        this.resolverParameter = configuration.getResolverParameter();
        this.jwtProcessors = new ConcurrentHashMap<>();
        this.jwtProcessorProvider = initJWTProcessorResolver(configuration);
    }

    @Override
    public Maybe<JWTProcessor<SecurityContext>> provide(HttpExecutionContext ctx) {
        if (jwtProcessorProvider == null) {
            return Maybe.empty();
        }

        return Maybe.defer(() -> {
            // Try to get the JWTProcessor from cache, based on raw resolver parameter.
            JWTProcessor<SecurityContext> jwtProcessor = jwtProcessors.get(resolverParameter);

            if (jwtProcessor != null) {
                return Maybe.just(jwtProcessor);
            }

            // Resolver parameter is probably an EL expression, evaluate and try to hit the cache again.
            final String resolvedParameter = ctx.getTemplateEngine().getValue(resolverParameter, String.class);

            // Put resolved parameter to be eventually reused by other processor providers and avoid multiple EL evaluations.
            ctx.putInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER, resolvedParameter);

            jwtProcessor = jwtProcessors.get(resolvedParameter);

            if (jwtProcessor != null) {
                return Maybe.just(jwtProcessor);
            }

            // JWTProcessor is not cached yet, create it.
            return jwtProcessorProvider.provide(ctx).doOnSuccess(p -> jwtProcessors.put(resolvedParameter, p));
        });
    }

    private JWTProcessorProvider initJWTProcessorResolver(JWTPolicyConfiguration configuration) {
        final KeyResolver publicKeyResolver = configuration.getPublicKeyResolver();

        if (publicKeyResolver == null) {
            return null;
        }

        switch (publicKeyResolver) {
            case GIVEN_KEY:
                return new GivenKeyJWTProcessorProvider(configuration);
            case JWKS_URL:
                return new JwksUrlJWTProcessorProvider(configuration);
            case GATEWAY_KEYS:
                return new GatewayKeysJWTProcessorProvider(configuration);
            default:
                throw new IllegalArgumentException("Unsupported key resolver " + publicKeyResolver);
        }
    }
}
