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
package io.gravitee.policy.jwt.contentretriever.vertx.authentication;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.impl.headers.HeadersMultiMap;

public class BearerTokenAuthenticationHandler implements AuthenticationHandler {

    private final String token;

    public BearerTokenAuthenticationHandler(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        this.token = token;
    }

    @Override
    public MultiMap getAuthenticationHeaders() {
        MultiMap headers = new HeadersMultiMap();
        headers.add(HttpHeaders.AUTHORIZATION.toString(), "Bearer " + token);
        return headers;
    }
}
