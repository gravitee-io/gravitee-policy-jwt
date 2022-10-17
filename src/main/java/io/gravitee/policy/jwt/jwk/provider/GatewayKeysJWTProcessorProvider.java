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

import static java.util.stream.Collectors.groupingBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.common.util.EnvironmentUtils;
import io.gravitee.gateway.jupiter.api.context.HttpExecutionContext;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.selector.IssuerAwareJWSKeySelector;
import io.gravitee.policy.jwt.jwk.selector.NoKidJWSVerificationKeySelector;
import io.gravitee.policy.jwt.utils.JWKBuilder;
import io.reactivex.rxjava3.core.Maybe;
import java.security.KeyException;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * {@link JWTProcessorProvider} based on {@link io.gravitee.policy.v3.jwt.resolver.KeyResolver#GATEWAY_KEYS}.
 * This provider iterates over the configuration to retrieve the keys and creates a {@link JWTProcessor} with the appropriate {@link JWSKeySelector}s.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
class GatewayKeysJWTProcessorProvider implements JWTProcessorProvider {

    protected static final String KEY_PROPERTY_PREFIX = "policy.jwt.issuer";
    private static final Logger log = LoggerFactory.getLogger(GatewayKeysJWTProcessorProvider.class);
    private static final String DEFAULT_KID = "default";
    private static final Pattern KEY_PROPERTY_PATTERN = Pattern.compile("^policy\\.jwt\\.issuer\\.(?<iss>.*)\\.(?<kid>.*)$");

    private final JWTPolicyConfiguration configuration;

    public GatewayKeysJWTProcessorProvider(final JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * {@inheritDoc}
     * Creates the {@link JWTProcessor} with all the keys defined at gateway level and cache it for reuse.
     */
    @Override
    public Maybe<JWTProcessor<SecurityContext>> provide(HttpExecutionContext ctx) {
        return Maybe.fromCallable(() -> buildJWTProcessor(ctx));
    }

    private JWTProcessor<SecurityContext> buildJWTProcessor(HttpExecutionContext ctx) {
        final JWSAlgorithm alg = configuration.getSignature().getAlg();
        final Map<String, List<JWK>> jwkByIssuer = loadFromConfiguration(alg, ctx.getComponent(ConfigurableEnvironment.class));
        final Map<String, JWSKeySelector<SecurityContext>> selectors = createJWSKeySelectors(alg, jwkByIssuer);

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWTClaimsSetAwareJWSKeySelector(new IssuerAwareJWSKeySelector(DEFAULT_KID, selectors));

        return jwtProcessor;
    }

    private Map<String, List<JWK>> loadFromConfiguration(JWSAlgorithm alg, ConfigurableEnvironment environment) {
        return EnvironmentUtils
            .getPropertiesStartingWith(environment, KEY_PROPERTY_PREFIX)
            .entrySet()
            .stream()
            .map(entry -> {
                final Matcher matcher = KEY_PROPERTY_PATTERN.matcher(entry.getKey());

                if (matcher.matches()) {
                    final String iss = matcher.group("iss");
                    final String kid = matcher.group("kid");
                    final String key = (String) entry.getValue();

                    try {
                        return new SimpleEntry<>(iss, JWKBuilder.buildKey(kid, key, alg));
                    } catch (KeyException e) {
                        log.warn("Error occurred when loading key (iss [{}], kid [{}]). Key will be ignored.", iss, kid, e);
                    }
                }

                return null;
            })
            .filter(Objects::nonNull)
            .collect(groupingBy(SimpleEntry::getKey, Collectors.mapping(SimpleEntry::getValue, Collectors.toList())));
    }

    private Map<String, JWSKeySelector<SecurityContext>> createJWSKeySelectors(JWSAlgorithm alg, Map<String, List<JWK>> jwkByIssuer) {
        return jwkByIssuer
            .entrySet()
            .stream()
            .collect(
                Collectors.toMap(
                    Map.Entry::getKey,
                    // Keep compatibility by ignoring Kid during verification.
                    e -> new NoKidJWSVerificationKeySelector<>(alg, new ImmutableJWKSet<>(new JWKSet(e.getValue())))
                )
            );
    }
}
