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

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ClaimPathResolver}.
 *
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ClaimPathResolverTest {

    // -----------------------------------------------------------------------
    // Nested hit
    // -----------------------------------------------------------------------

    @Test
    void should_resolve_nested_claim_with_dot_notation() {
        JSONObject act = new JSONObject();
        act.put("repository", "myorg/my-repo");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("act", act)
            .build();

        Object result = ClaimPathResolver.resolve(claims, "act.repository");

        assertThat(result).isEqualTo("myorg/my-repo");
    }

    @Test
    void should_resolve_deeply_nested_claim() {
        JSONObject inner = new JSONObject();
        inner.put("id", "deep-value");

        JSONObject outer = new JSONObject();
        outer.put("inner", inner);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("outer", outer)
            .build();

        Object result = ClaimPathResolver.resolve(claims, "outer.inner.id");

        assertThat(result).isEqualTo("deep-value");
    }

    // -----------------------------------------------------------------------
    // Flat hit (no dot in name)
    // -----------------------------------------------------------------------

    @Test
    void should_resolve_flat_top_level_claim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("alexluso")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("client_id", "my-client")
            .build();

        Object result = ClaimPathResolver.resolve(claims, "client_id");

        assertThat(result).isEqualTo("my-client");
    }

    // -----------------------------------------------------------------------
    // Flat-with-literal-dot wins over nested walk (flat-first fallback)
    // -----------------------------------------------------------------------

    @Test
    void should_return_flat_claim_when_literal_dot_name_exists_at_top_level() {
        // A claim whose name literally contains a dot must win over nested resolution.
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("x.y", "flat-value")
            .build();

        Object result = ClaimPathResolver.resolve(claims, "x.y");

        assertThat(result).isEqualTo("flat-value");
    }

    // -----------------------------------------------------------------------
    // Missing mid-path
    // -----------------------------------------------------------------------

    @Test
    void should_return_null_when_intermediate_segment_is_missing() {
        JSONObject act = new JSONObject();
        act.put("repository", "myorg/my-repo");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("act", act)
            .build();

        Object result = ClaimPathResolver.resolve(claims, "act.missing.field");

        assertThat(result).isNull();
    }

    @Test
    void should_return_null_when_first_segment_does_not_exist() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .build();

        Object result = ClaimPathResolver.resolve(claims, "nonexistent.field");

        assertThat(result).isNull();
    }

    // -----------------------------------------------------------------------
    // Non-Map mid-path
    // -----------------------------------------------------------------------

    @Test
    void should_return_null_when_intermediate_value_is_not_a_map() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("alexluso") // subject is a String, not a Map
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .build();

        // "sub" is a String, so walking "sub.nested" must return null.
        Object result = ClaimPathResolver.resolve(claims, "sub.nested");

        assertThat(result).isNull();
    }

    // -----------------------------------------------------------------------
    // Null / empty guard conditions
    // -----------------------------------------------------------------------

    @Test
    void should_return_null_when_claims_is_null() {
        assertThat(ClaimPathResolver.resolve(null, "act.repository")).isNull();
    }

    @Test
    void should_return_null_when_name_is_null() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .build();

        assertThat(ClaimPathResolver.resolve(claims, null)).isNull();
    }

    @Test
    void should_return_null_when_name_is_empty() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("sub")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .build();

        assertThat(ClaimPathResolver.resolve(claims, "")).isNull();
    }

    // -----------------------------------------------------------------------
    // Back-compat: standard flat claim name (no dot) still resolves
    // -----------------------------------------------------------------------

    @Test
    void should_resolve_standard_sub_claim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .subject("john.doe@example.com")
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .build();

        Object result = ClaimPathResolver.resolve(claims, "sub");

        assertThat(result).isEqualTo("john.doe@example.com");
    }
}
