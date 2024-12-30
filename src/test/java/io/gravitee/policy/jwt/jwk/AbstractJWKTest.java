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
package io.gravitee.policy.jwt.jwk;

import static org.junit.jupiter.api.Assertions.fail;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.policy.jwt.alg.Signature;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Stream;
import net.schmizz.sshj.common.Buffer;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.params.provider.Arguments;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public abstract class AbstractJWKTest {

    protected static Stream<Arguments> provideRSAParameters() {
        return Stream.of(
            Arguments.of(2048, Signature.RSA_RS256),
            Arguments.of(2048, Signature.RSA_RS384),
            Arguments.of(2048, Signature.RSA_RS512)
        );
    }

    protected static Stream<Arguments> provideHMACParameters() {
        return Stream.of(
            Arguments.of(32, Signature.HMAC_HS256),
            Arguments.of(48, Signature.HMAC_HS384),
            Arguments.of(64, Signature.HMAC_HS512)
        );
    }

    protected static Stream<Arguments> provideHMACWithOptionalBase64Parameters() {
        return Stream.of(
            Arguments.of(32, Signature.HMAC_HS256, false),
            Arguments.of(32, Signature.HMAC_HS256, true),
            Arguments.of(48, Signature.HMAC_HS384, false),
            Arguments.of(48, Signature.HMAC_HS384, true),
            Arguments.of(64, Signature.HMAC_HS512, false),
            Arguments.of(64, Signature.HMAC_HS512, true)
        );
    }

    protected KeyPair generateKeyPair(int size, Algorithm alg) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(getAlgorithmFamily(alg));
            kpg.initialize(size);

            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            fail(e);
        }

        return fail();
    }

    protected String toSSHPublicKeyFormat(PublicKey publicKey) {
        final byte[] compactData = new Buffer.PlainBuffer().putPublicKey(publicKey).getCompactData();
        return "ssh-rsa " + Base64.getEncoder().encodeToString(compactData);
    }

    protected String toPEMFormat(PublicKey publicKey) {
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----";
    }

    protected String getAlgorithmFamily(Algorithm algorithm) {
        if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
            return "RSA";
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
            return "HMAC";
        }
        return null;
    }

    protected String generateJWT(RSAKey key, String issuer, String keyID) throws Exception {
        final JWSSigner signer = new RSASSASigner(key);

        final JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) key.getAlgorithm())
            .keyID(keyID)
            .customParam("test", "value")
            .contentType("text/plain")
            .build();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new SignedJWT(header, claimsSet);

        // Compute the RSA signature
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    protected String generateJWT(byte[] sharedSecret, JWSAlgorithm algorithm, String issuer, String keyID) throws Exception {
        final JWSSigner signer = new MACSigner(sharedSecret);

        final JWSHeader header = new JWSHeader.Builder(algorithm)
            .keyID(keyID)
            .customParam("test", "value")
            .contentType("text/plain")
            .build();

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .expirationTime(new Date(System.currentTimeMillis() + 3600000))
            .build();

        // Prepare JWS object with simple string as payload
        JWSObject jwsObject = new SignedJWT(header, claimsSet);

        // Compute the RSA signature
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    protected byte[] generateHMACKey(Integer keySize) {
        return RandomStringUtils.random(keySize).getBytes();
    }
}
