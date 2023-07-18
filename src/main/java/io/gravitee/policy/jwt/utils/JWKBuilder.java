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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWKBuilder {

    public static JWK buildKey(String keyId, String keyValue, JWSAlgorithm alg) throws KeyException {
        if (JWSAlgorithm.Family.RSA.contains(alg)) {
            return buildRSAKey(keyId, keyValue, alg);
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
            return buildHMACKey(keyId, keyValue, alg);
        }

        throw new KeyException("Key algorithm not supported: " + alg.getName());
    }

    public static JWK buildRSAKey(String keyId, String keyValue, JWSAlgorithm alg) throws KeyException {
        final RSAPublicKey rsaPublicKey;

        if (keyValue.startsWith("ssh-rsa")) {
            rsaPublicKey = PublicKeyHelper.parsePublicKey(keyValue);
        } else {
            try {
                JWK jwk = JWK.parseFromPEMEncodedObjects(keyValue);
                rsaPublicKey = ((RSAKey) jwk).toRSAPublicKey();
            } catch (JOSEException e) {
                throw new KeyException("Invalid key (kid: " + keyId + ", alg: " + alg.getName() + ")", e);
            }
        }

        if (rsaPublicKey != null) {
            return new RSAKey.Builder(rsaPublicKey).keyID(keyId).algorithm(alg).build();
        }

        throw new KeyException("Invalid key (kid: " + keyId + ", alg: " + alg.getName() + ")");
    }

    public static JWK buildHMACKey(String keyId, String keyValue, JWSAlgorithm alg) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(keyValue);
        } catch (IllegalArgumentException e) {
            key = keyValue.getBytes();
        }
        return new OctetSequenceKey.Builder(key).keyID(keyId).algorithm(alg).build();
    }
}
