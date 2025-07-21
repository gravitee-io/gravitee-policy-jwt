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
package io.gravitee.policy.jwt.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RevocationCheckTest {

    private JWTPolicyConfiguration.RevocationCheck revocationCheck;

    @BeforeEach
    void setUp() {
        revocationCheck = new JWTPolicyConfiguration.RevocationCheck();
    }

    @Test
    void shouldBeInvalidWhenRevocationListUrlIsNull() {
        revocationCheck.setEnabled(true);
        revocationCheck.setRevocationListUrl(null);

        assertThat(revocationCheck.isValid()).isFalse();
    }

    @Test
    void shouldBeInvalidWhenRevocationListUrlIsEmpty() {
        revocationCheck.setEnabled(true);
        revocationCheck.setRevocationListUrl("");

        assertThat(revocationCheck.isValid()).isFalse();
    }

    @Test
    void shouldBeInvalidWhenRevocationListUrlIsMalformed() {
        revocationCheck.setEnabled(true);
        revocationCheck.setRevocationListUrl("not_a_valid_url");

        assertThat(revocationCheck.isValid()).isFalse();
    }

    @Test
    void shouldNormalizeWithDefaultValuesWhenAttributesAreNull() {
        revocationCheck.setRefreshInterval(null);
        revocationCheck.setRevocationClaim(null);
        revocationCheck.setConnectTimeout(null);
        revocationCheck.setRequestTimeout(null);

        JWTPolicyConfiguration.RevocationCheck normalized = revocationCheck.normalized();

        assertThat(normalized.getRefreshInterval()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REFRESH_INTERVAL);
        assertThat(normalized.getRevocationClaim()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REVOCATION_CLAIM);
        assertThat(normalized.getConnectTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_CONNECT_TIMEOUT);
        assertThat(normalized.getRequestTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REQUEST_TIMEOUT);
    }

    @Test
    void shouldNormalizeWithDefaultValuesWhenTimeoutsAreNegative() {
        revocationCheck.setConnectTimeout(-1);
        revocationCheck.setRequestTimeout(-1L);

        JWTPolicyConfiguration.RevocationCheck normalized = revocationCheck.normalized();

        assertThat(normalized.getConnectTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_CONNECT_TIMEOUT);
        assertThat(normalized.getRequestTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REQUEST_TIMEOUT);
    }

    @Test
    void shouldNormalizeWithDefaultValuesWhenRefreshIntervalIsNegative() {
        revocationCheck.setRefreshInterval(-1);

        JWTPolicyConfiguration.RevocationCheck normalized = revocationCheck.normalized();

        assertThat(normalized.getRefreshInterval()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REFRESH_INTERVAL);
    }

    @Test
    void shouldNormalizeWithDefaultValuesWhenRevocationClaimIsEmpty() {
        revocationCheck.setRevocationClaim("");

        JWTPolicyConfiguration.RevocationCheck normalized = revocationCheck.normalized();

        assertThat(normalized.getRevocationClaim()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REVOCATION_CLAIM);
    }

    @Test
    void shouldKeepValidValuesWhenNormalizing() {
        revocationCheck.setRefreshInterval(600);
        revocationCheck.setRevocationClaim("custom-jti");
        revocationCheck.setRevocationListUrl("http://example.com/revocation-list");
        revocationCheck.setConnectTimeout(5000);
        revocationCheck.setRequestTimeout(5000L);
        revocationCheck.setFollowRedirects(true);
        revocationCheck.setUseSystemProxy(true);

        JWTPolicyConfiguration.RevocationCheck normalized = revocationCheck.normalized();

        assertThat(normalized.getRefreshInterval()).isEqualTo(600);
        assertThat(normalized.getRevocationClaim()).isEqualTo("custom-jti");
        assertThat(normalized.getRevocationListUrl()).isEqualTo("http://example.com/revocation-list");
        assertThat(normalized.getConnectTimeout()).isEqualTo(5000);
        assertThat(normalized.getRequestTimeout()).isEqualTo(5000L);
        assertThat(normalized.isFollowRedirects()).isTrue();
        assertThat(normalized.isUseSystemProxy()).isTrue();
    }

    @Test
    void shouldHaveCorrectDefaultValues() {
        assertThat(revocationCheck.isEnabled()).isFalse();
        assertThat(revocationCheck.getRevocationClaim()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REVOCATION_CLAIM);
        assertThat(revocationCheck.getRefreshInterval()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REFRESH_INTERVAL);
        assertThat(revocationCheck.getConnectTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_CONNECT_TIMEOUT);
        assertThat(revocationCheck.getRequestTimeout()).isEqualTo(JWTPolicyConfiguration.RevocationCheck.DEFAULT_REQUEST_TIMEOUT);
        assertThat(revocationCheck.isFollowRedirects()).isFalse();
        assertThat(revocationCheck.isUseSystemProxy()).isFalse();
    }
}
