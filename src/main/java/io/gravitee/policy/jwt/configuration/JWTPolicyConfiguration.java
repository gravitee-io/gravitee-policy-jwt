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
package io.gravitee.policy.jwt.configuration;

import io.gravitee.policy.api.PolicyConfiguration;

/**
 * @author Alexandre FARIA (alexandre82.faria at gmail.com)
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTPolicyConfiguration implements PolicyConfiguration {

    //settings attributes
    private String resolverParameter;
    private KeyResolver publicKeyResolver = KeyResolver.GIVEN_KEY;
    private boolean extractClaims = false;
    
    //getter and setters
    public KeyResolver getPublicKeyResolver() {
        return publicKeyResolver;
    }

    public void setPublicKeyResolver(KeyResolver publicKeyResolver) {
        this.publicKeyResolver = publicKeyResolver;
    }
    
    public String getResolverParameter() {
        return resolverParameter;
    }
    
    public void setResolverParameter(String givenKey) {
        this.resolverParameter = givenKey;
    }

    public boolean isExtractClaims() {
        return extractClaims;
    }

    public void setExtractClaims(boolean extractClaims) {
        this.extractClaims = extractClaims;
    }
}
