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
package io.gravitee.policy.helpers;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.UUID;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JWTTokenGenerator {

    /**
     * Generates a valid signed JSON Web Token (JWT) using the HS256 algorithm. The token includes
     * predefined claims such as subject, issuer, audience, name, role, issue time, expiration time,
     * and a unique identifier. The expiration time is determined by the validity duration provided.
     *
     * @param tokenValidityInMs the duration in milliseconds for which the token should remain valid.
     * @return a {@link SignedJWT} object representing the generated and signed token.
     * @throws RuntimeException if an exception occurs during the signing process.
     */
    public static SignedJWT createValidSignedToken(Long tokenValidityInMs) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).keyID("key").build();

        Date now = new Date();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("user123")
            .issuer("gravitee")
            .audience("api-gateway")
            .claim("name", "John Doe")
            .claim("role", "admin")
            .issueTime(now)
            .expirationTime(new Date(now.toInstant().toEpochMilli() + tokenValidityInMs))
            .jwtID(UUID.randomUUID().toString())
            .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        JWSSigner signer = null;
        try {
            signer = new MACSigner("a-very-long-key-at-least-256-bits");
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT;
    }
}
