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
package io.gravitee.policy.jwt.jwk.source;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.JWTProcessor;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Specific implementation of {@link JWKSource} allowing to cache a {@link JWKSource} and save its cache date to allow triggering refresh.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class CachedJWKSource<C extends SecurityContext> implements JWKSource<C> {

    private final LocalDateTime cacheDateTime;

    private final JWKSource<C> jwkSource;

    public CachedJWKSource(JWKSource<C> jwkSource) {
        this.cacheDateTime = LocalDateTime.now();
        this.jwkSource = jwkSource;
    }

    public LocalDateTime getCacheDateTime() {
        return cacheDateTime;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
        return jwkSource.get(jwkSelector, context);
    }

    public boolean isCacheExpired(Duration refreshInterval) {
        return Duration.between(getCacheDateTime(), LocalDateTime.now()).compareTo(refreshInterval) > 0;
    }
}
