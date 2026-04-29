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
package io.gravitee.policy.jwt.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Map;

/**
 * Resolves claim values from a {@link JWTClaimsSet} using dot-notation paths.
 *
 * <p>Resolution order:
 * <ol>
 *   <li><strong>Flat lookup first</strong> — {@code claims.getClaim(name)} is tried first.
 *       If the result is non-null it is returned immediately. This preserves backward
 *       compatibility for existing configurations whose claim name literally contains a
 *       dot (e.g. {@code "x.y": "value"}).</li>
 *   <li><strong>Nested walk</strong> — when the flat lookup returns {@code null} and the
 *       name contains at least one {@code '.'}, the name is split on {@code '.'} and the
 *       resolver walks successive {@link Map} values. Nimbus represents nested JSON objects
 *       as {@code net.minidev.json.JSONObject}, which extends {@code Map<String, Object>}.</li>
 *   <li>Returns {@code null} when any segment is missing, when an intermediate value is
 *       not a {@link Map}, or when either argument is {@code null} / empty.</li>
 * </ol>
 *
 * @author GraviteeSource Team
 */
public final class ClaimPathResolver {

    private ClaimPathResolver() {}

    /**
     * Resolves a claim value from the given {@link JWTClaimsSet} using the supplied name.
     * Supports dot-notation nested paths (e.g. {@code "act.repository"}).
     *
     * @param claims the JWT claims set to resolve from; may be {@code null}
     * @param name   the claim name or dot-notation path; may be {@code null} or empty
     * @return the resolved claim value, or {@code null} if not found
     */
    public static Object resolve(JWTClaimsSet claims, String name) {
        if (claims == null || name == null || name.isEmpty()) {
            return null;
        }

        // 1. Flat lookup — covers the common case and preserves backward compatibility
        //    for claim names that literally contain a dot.
        Object flatValue = claims.getClaim(name);
        if (flatValue != null) {
            return flatValue;
        }

        // 2. Nested walk — only attempted when the flat lookup misses and the name has dots.
        if (!name.contains(".")) {
            return null;
        }

        String[] segments = name.split("\\.", -1);

        // First segment must resolve to a top-level claim.
        Object current = claims.getClaim(segments[0]);

        for (int i = 1; i < segments.length; i++) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = map.get(segments[i]);
            if (current == null) {
                return null;
            }
        }

        return current;
    }
}
