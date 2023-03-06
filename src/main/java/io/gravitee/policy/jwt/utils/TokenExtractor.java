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
package io.gravitee.policy.jwt.utils;

import io.gravitee.common.util.MultiValueMap;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.HttpRequest;
import io.gravitee.gateway.reactive.api.context.Request;
import java.util.List;
import java.util.Optional;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class TokenExtractor {

    static final String BEARER = "Bearer";
    static final String ACCESS_TOKEN = "access_token";

    /**
     * Extract a jwt token from a {@link Request} headers or parameters.
     * <ul>
     *     <li>Get the first <code>Authorization</code> bearer header</li>
     *     <li>If no header, try to find an <code>access_token</code> query parameter</li>
     * </ul>
     *
     * If no jwt token has been found, an {@link Optional#empty()} is returned.
     *
     * @param request the request to extract the JWT token from.
     *
     * @return the jwt token as string, {@link Optional#empty()} if no token has been found.
     * @throws AuthorizationSchemeException in case of malformed Authorization bearer or not supported Authorization scheme.
     * @see #lookFor(HttpRequest)
     */
    public static Optional<String> extract(HttpRequest request) throws AuthorizationSchemeException {
        return extractFromHeaders(request.headers()).or(() -> extractFromParameters(request.parameters()));
    }

    /**
     * Same as {@link #extract(HttpRequest)} but silently capture potential {@link AuthorizationSchemeException} and return empty instead.
     *
     * @param request the request to extract the JWT token from.
     *
     * @return the jwt token as string, {@link Optional#empty()} if no token has been found or is malformed.
     */
    public static Optional<String> lookFor(HttpRequest request) {
        try {
            return extract(request);
        } catch (AuthorizationSchemeException e) {
            return Optional.empty();
        }
    }

    private static Optional<String> extractFromHeaders(HttpHeaders headers) throws AuthorizationSchemeException {
        if (headers != null) {
            List<String> authorizationHeaders = headers.getAll(HttpHeaderNames.AUTHORIZATION);

            if (!ObjectUtils.isEmpty(authorizationHeaders)) {
                Optional<String> authorizationBearerHeader = authorizationHeaders
                    .stream()
                    .filter(h -> StringUtils.startsWithIgnoreCase(h, BEARER))
                    .findFirst();

                if (authorizationBearerHeader.isPresent()) {
                    String authToken = authorizationBearerHeader.get().substring(BEARER.length()).trim();
                    if (!authToken.isEmpty()) {
                        return Optional.of(authToken);
                    } else {
                        throw new AuthorizationSchemeException("Authorization scheme is not supported for JWT");
                    }
                } else {
                    throw new AuthorizationSchemeException("Authorization scheme not found");
                }
            }
        }

        return Optional.empty();
    }

    private static Optional<String> extractFromParameters(MultiValueMap<String, String> parameters) {
        if (parameters != null) {
            return Optional.ofNullable(parameters.getFirst(TokenExtractor.ACCESS_TOKEN));
        }

        return Optional.empty();
    }

    /**
     * @deprecated kept for v3
     *
     * @param request the request to extract the JWT token from.
     * @return the jwt token as string or <code>null</code> if no token has been found.
     * @see #extract(HttpRequest)
     */
    @Deprecated
    public static String extract(io.gravitee.gateway.api.Request request) throws AuthorizationSchemeException {
        return extractFromHeaders(request.headers()).or(() -> extractFromParameters(request.parameters())).orElse(null);
    }

    /**
     * @author Guillaume Gillon (guillaume.gillon at outlook.com)
     */
    public static class AuthorizationSchemeException extends Exception {

        private static final long serialVersionUID = 2790902079107614511L;

        public AuthorizationSchemeException(String message) {
            super(message);
        }
    }
}
