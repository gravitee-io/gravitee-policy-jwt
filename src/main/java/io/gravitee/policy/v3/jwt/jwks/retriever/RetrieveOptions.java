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
package io.gravitee.policy.v3.jwt.jwks.retriever;

import java.util.Optional;
import lombok.Builder;
import lombok.Value;

/**
 * @author Antoine CORDIER (antoine.cordier at graviteesource.com)
 * @author GraviteeSource Team
 */
@Value
@Builder
public class RetrieveOptions {

    private static final int DEFAULT_CONNECT_TIMEOUT = 2000;
    private static final long DEFAULT_REQUEST_TIMEOUT = 2000L;

    boolean useSystemProxy;
    Integer connectTimeout;
    Long requestTimeout;

    public int getConnectTimeout() {
        return Optional.ofNullable(connectTimeout).orElse(DEFAULT_CONNECT_TIMEOUT);
    }

    public long getRequestTimeout() {
        return Optional.ofNullable(requestTimeout).orElse(DEFAULT_REQUEST_TIMEOUT);
    }
}
