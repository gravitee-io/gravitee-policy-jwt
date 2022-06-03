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
package io.gravitee.policy.v3.jwt.jwks;

import com.nimbusds.jose.jwk.source.JWKSource;
import java.time.LocalDateTime;

/**
 * @author GraviteeSource Team
 */
public class CachedJWKSource {

    private LocalDateTime cacheDateTime;

    private JWKSource jwkSource;

    public CachedJWKSource(JWKSource jwkSource) {
        this.cacheDateTime = LocalDateTime.now();
        this.jwkSource = jwkSource;
    }

    public LocalDateTime getCacheDateTime() {
        return cacheDateTime;
    }

    public JWKSource getJwkSource() {
        return jwkSource;
    }
}
