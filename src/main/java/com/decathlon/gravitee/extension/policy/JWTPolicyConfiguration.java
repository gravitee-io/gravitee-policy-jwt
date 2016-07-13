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
package com.decathlon.gravitee.extension.policy;

import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.common.http.HttpMethod;

@SuppressWarnings("unused")
public class JWTPolicyConfiguration implements PolicyConfiguration {

    /**
     * A String parameter
     */
    private String stringParam = "defaultValue";

    /**
     * A integer parameter
     */
    private int integerParam;

    /**
     * A integer parameter
     */
    private boolean booleanParam;

    /**
     * An enum parameter
     */
    private HttpMethod httpMethod;

    /**
     * Get the String parameter
     *
     * @return the String parameter
     */
    public String getStringParam() {
        return stringParam;
    }

    /**
     * Get the integer parameter
     *
     * @return the integer parameter
     */
    public int getIntegerParam() {
        return integerParam;
    }

    /**
     * Get the boolean parameter
     *
     * @return the boolean parameter
     */
    public boolean getBooleanParam() {
        return booleanParam;
    }

    public HttpMethod getHttpMethod() {
        return httpMethod;
    }
}
