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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.util.Base64;
import java.util.UUID;

public class TestNimbus {

    public static void main(String[] args) throws JOSEException {
        RSAKey jwk = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.ENCRYPTION) // indicate the intended use of the key
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID
                .generate();

        RSAKey recipientPublicJWK = jwk.toPublicJWK();

        Base64.Encoder encoder = Base64.getEncoder();
        String publicKeyStr = encoder.encodeToString(recipientPublicJWK.toPublicKey().getEncoded());
        //String privateKeyStr = encoder.encodeToString(recipientPublicJWK.toPrivateKey().getEncoded());



        System.out.println(publicKeyStr);
        //System.out.println(privateKeyStr);
    }
}
