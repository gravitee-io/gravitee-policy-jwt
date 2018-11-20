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
package io.gravitee.policy.jwt;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import io.gravitee.policy.jwt.alg.Signature;

import java.security.SecureRandom;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class HMACJWTPolicyTest extends JWTPolicyTest {

    private static String SECRET;

    static {
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);
        SECRET = new String(sharedSecret);
    }

    protected Signature getSignature() {
        return Signature.HMAC_HS256;
    }

    protected JWSSigner getSigner() throws Exception {
        return new MACSigner(new OctetSequenceKey.Builder(SECRET.getBytes()).build());
    }

    @Override
    protected String getSignatureKey() throws Exception {
        return SECRET;
    }

    /*
    @Test
    public void test_hmac256_with_given_key_and_valid_authorization_header() throws Exception {
        String jwt = getJsonWebToken(7200);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwt);
        when(request.headers()).thenReturn(headers);
        when(configuration.getPublicKeyResolver()).thenReturn(KeyResolver.GIVEN_KEY);
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getResolverParameter()).thenReturn(SECRET);
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(SECRET)).thenReturn(SECRET);

        executePolicy(configuration, request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
    }
    */
}
