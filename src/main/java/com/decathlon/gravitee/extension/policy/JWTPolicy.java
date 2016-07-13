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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.OnResponse;
import io.jsonwebtoken.Jwts;

@SuppressWarnings("unused")
public class JWTPolicy {

    /**
     * The associated configuration to this JWT Policy
     */
    private JWTPolicyConfiguration configuration;

    /**
     * Create a new JWT Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new JWT Policy instance
     */
    public JWTPolicy(JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {
        try {
            String jwt = request.headers().getFirst(HttpHeaders.AUTHORIZATION).split(" ")[1];
            if (jwt == null) {
                jwt = request.parameters().get("access_token");
            }

            final String iss = (String) Jwts.parser().parse(jwt).getHeader().get("iss");
            final String key = configuration.getPublicKey(iss);
            Jwts.parser().setSigningKey(key).parseClaimsJwt(jwt);
            policyChain.doNext(request, response);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized via JWT"));
        }
    }
}
