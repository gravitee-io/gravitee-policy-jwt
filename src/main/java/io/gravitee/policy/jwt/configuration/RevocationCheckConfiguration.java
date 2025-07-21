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

import java.net.MalformedURLException;
import java.net.URL;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@NoArgsConstructor
@Getter
@Slf4j
public class RevocationCheckConfiguration {

    public static final Integer DEFAULT_REFRESH_INTERVAL = 300;
    public static final Integer DEFAULT_CONNECT_TIMEOUT = 2000;
    public static final Long DEFAULT_REQUEST_TIMEOUT = 2000L;
    public static final String DEFAULT_REVOCATION_CLAIM = "jti";

    @Setter
    private boolean enabled = false;

    private String revocationClaim = DEFAULT_REVOCATION_CLAIM;

    @Setter
    private String revocationListUrl;

    private Integer refreshInterval = DEFAULT_REFRESH_INTERVAL;

    private Integer connectTimeout = DEFAULT_CONNECT_TIMEOUT;

    private Long requestTimeout = DEFAULT_REQUEST_TIMEOUT;

    @Setter
    private boolean followRedirects = false;

    @Setter
    private boolean useSystemProxy = false;

    @Setter
    private AuthConfiguration auth = new AuthConfiguration();

    public RevocationCheckConfiguration(
        boolean enabled,
        String revocationClaim,
        String revocationListUrl,
        Integer refreshInterval,
        Integer connectTimeout,
        Long requestTimeout,
        boolean followRedirects,
        boolean useSystemProxy,
        AuthConfiguration auth
    ) {
        setEnabled(enabled);
        setRevocationClaim(revocationClaim);
        setRevocationListUrl(revocationListUrl);
        setRefreshInterval(refreshInterval);
        setConnectTimeout(connectTimeout);
        setRequestTimeout(requestTimeout);
        setFollowRedirects(followRedirects);
        setUseSystemProxy(useSystemProxy);
        setAuth(auth);
    }

    public void setRefreshInterval(Integer refreshInterval) {
        if (refreshInterval == null || refreshInterval <= 0) {
            log.warn(
                "Revocation list refresh interval is not defined or is not a positive number. Using default value of {} seconds.",
                DEFAULT_REFRESH_INTERVAL
            );
            this.refreshInterval = DEFAULT_REFRESH_INTERVAL;
        } else {
            this.refreshInterval = refreshInterval;
        }
    }

    public void setRevocationClaim(String revocationClaim) {
        if (revocationClaim == null || revocationClaim.isEmpty()) {
            log.warn("Revocation claim is not defined in policy configuration. Using default value of {}.", DEFAULT_REVOCATION_CLAIM);
            this.revocationClaim = DEFAULT_REVOCATION_CLAIM;
        } else {
            this.revocationClaim = revocationClaim;
        }
    }

    public void setConnectTimeout(Integer connectTimeout) {
        if (connectTimeout == null || connectTimeout <= 0) {
            log.warn(
                "Revocation list connect timeout is not defined or is not a positive number. Using default value of {} ms.",
                DEFAULT_CONNECT_TIMEOUT
            );
            this.connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        } else {
            this.connectTimeout = connectTimeout;
        }
    }

    public void setRequestTimeout(Long requestTimeout) {
        if (requestTimeout == null || requestTimeout <= 0) {
            log.warn(
                "Revocation list request timeout is not defined or is not a positive number. Using default value of {} ms.",
                DEFAULT_REQUEST_TIMEOUT
            );
            this.requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        } else {
            this.requestTimeout = requestTimeout;
        }
    }

    public static boolean isEnabledAndValid(RevocationCheckConfiguration config) {
        if (!config.enabled) {
            return false;
        }

        if (config.revocationListUrl == null || config.revocationListUrl.isEmpty()) {
            log.error("Revocation list url is not defined in policy configuration so revocation check will not be initialized");
            return false;
        }

        try {
            new URL(config.revocationListUrl);
        } catch (MalformedURLException e) {
            log.error("Invalid revocation list URL format so revocation check will not be initialized: {}", config.revocationListUrl);
            return false;
        }

        return true;
    }
}
