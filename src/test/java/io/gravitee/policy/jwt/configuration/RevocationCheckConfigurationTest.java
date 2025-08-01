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

import static io.gravitee.policy.jwt.configuration.RevocationCheckConfiguration.*;
import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCheckConfigurationTest {

    @Test
    void constructor_should_properly_set_all_values() {
        String revocationClaim = "custom-jti";
        String revocationListUrl = "http://example.com";
        Integer refreshInterval = 600;
        Integer connectTimeout = 5000;
        Long requestTimeout = 5000L;
        boolean enabled = true;
        boolean followRedirects = true;
        boolean useSystemProxy = true;
        AuthConfiguration auth = new AuthConfiguration();

        RevocationCheckConfiguration config = new RevocationCheckConfiguration(
            enabled,
            revocationClaim,
            revocationListUrl,
            refreshInterval,
            connectTimeout,
            requestTimeout,
            followRedirects,
            useSystemProxy,
            auth
        );

        assertThat(config.isEnabled()).isEqualTo(enabled);
        assertThat(config.getRevocationClaim()).isEqualTo(revocationClaim);
        assertThat(config.getRevocationListUrl()).isEqualTo(revocationListUrl);
        assertThat(config.getRefreshInterval()).isEqualTo(refreshInterval);
        assertThat(config.getConnectTimeout()).isEqualTo(connectTimeout);
        assertThat(config.getRequestTimeout()).isEqualTo(requestTimeout);
        assertThat(config.isFollowRedirects()).isEqualTo(followRedirects);
        assertThat(config.isUseSystemProxy()).isEqualTo(useSystemProxy);
        assertThat(config.getAuth()).isEqualTo(auth);
    }

    @Test
    void setRefreshInterval_should_use_default_when_null() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRefreshInterval(null);

        assertThat(config.getRefreshInterval()).isEqualTo(DEFAULT_REFRESH_INTERVAL);
    }

    @Test
    void setRefreshInterval_should_use_default_when_negative() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRefreshInterval(-1);

        assertThat(config.getRefreshInterval()).isEqualTo(DEFAULT_REFRESH_INTERVAL);
    }

    @Test
    void setRefreshInterval_should_use_provided_value_when_positive() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        Integer validInterval = 600;

        config.setRefreshInterval(validInterval);

        assertThat(config.getRefreshInterval()).isEqualTo(validInterval);
    }

    @Test
    void setRevocationClaim_should_use_default_when_null() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRevocationClaim(null);

        assertThat(config.getRevocationClaim()).isEqualTo(DEFAULT_REVOCATION_CLAIM);
    }

    @Test
    void setRevocationClaim_should_use_default_when_empty() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRevocationClaim("");

        assertThat(config.getRevocationClaim()).isEqualTo(DEFAULT_REVOCATION_CLAIM);
    }

    @Test
    void setRevocationClaim_should_use_provided_value_when_valid() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        String validClaim = "custom-jti";

        config.setRevocationClaim(validClaim);

        assertThat(config.getRevocationClaim()).isEqualTo(validClaim);
    }

    @Test
    void setConnectTimeout_should_use_default_when_null() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setConnectTimeout(null);

        assertThat(config.getConnectTimeout()).isEqualTo(DEFAULT_CONNECT_TIMEOUT);
    }

    @Test
    void setConnectTimeout_should_use_default_when_negative() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setConnectTimeout(-1);

        assertThat(config.getConnectTimeout()).isEqualTo(DEFAULT_CONNECT_TIMEOUT);
    }

    @Test
    void setConnectTimeout_should_use_provided_value_when_positive() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        Integer validTimeout = 5000;

        config.setConnectTimeout(validTimeout);

        assertThat(config.getConnectTimeout()).isEqualTo(validTimeout);
    }

    @Test
    void setRequestTimeout_should_use_default_when_null() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRequestTimeout(null);

        assertThat(config.getRequestTimeout()).isEqualTo(DEFAULT_REQUEST_TIMEOUT);
    }

    @Test
    void setRequestTimeout_should_use_default_when_negative() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();

        config.setRequestTimeout(-1L);

        assertThat(config.getRequestTimeout()).isEqualTo(DEFAULT_REQUEST_TIMEOUT);
    }

    @Test
    void setRequestTimeout_should_use_provided_value_when_positive() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        Long validTimeout = 5000L;

        config.setRequestTimeout(validTimeout);

        assertThat(config.getRequestTimeout()).isEqualTo(validTimeout);
    }

    @Test
    void isEnabledAndValid_should_return_false_when_disabled() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        config.setEnabled(false);
        config.setRevocationListUrl("http://valid-url.com");

        assertThat(RevocationCheckConfiguration.isEnabledAndValid(config)).isFalse();
    }

    @Test
    void isEnabledAndValid_should_return_false_when_url_is_null() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        config.setEnabled(true);
        config.setRevocationListUrl(null);

        assertThat(RevocationCheckConfiguration.isEnabledAndValid(config)).isFalse();
    }

    @Test
    void isEnabledAndValid_should_return_false_when_url_is_empty() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        config.setEnabled(true);
        config.setRevocationListUrl("");

        assertThat(RevocationCheckConfiguration.isEnabledAndValid(config)).isFalse();
    }

    @Test
    void isEnabledAndValid_should_return_false_when_url_is_malformed() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        config.setEnabled(true);
        config.setRevocationListUrl("not-a-valid-url");

        assertThat(RevocationCheckConfiguration.isEnabledAndValid(config)).isFalse();
    }

    @Test
    void isEnabledAndValid_should_return_true_when_enabled_and_url_is_valid() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration();
        config.setEnabled(true);
        config.setRevocationListUrl("http://valid-url.com");

        assertThat(RevocationCheckConfiguration.isEnabledAndValid(config)).isTrue();
    }
}
