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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.jsonwebtoken.*;
import org.springframework.core.env.Environment;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("unused")
public class JWTPolicy {

    /**
     * The associated configuration to this JWT Policy
     */
    private JWTPolicyConfiguration configuration;

    private final static String DEFAULT_KID = "default";
    private final static String PUBLIC_KEY_PROPERTY = "policy.jwt.issuer.%s.%s";

    /**
     * Create a new JWT Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new JWT Policy instance
     */
    public JWTPolicy(JWTPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        try {
            String jwt = request.headers().getFirst(HttpHeaders.AUTHORIZATION).split(" ")[1];
            if (jwt == null) {
                jwt = request.parameters().get("access_token");
            }

            SigningKeyResolver resolver = new SigningKeyResolverAdapter() {

                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {

                    String keyId = header.getKeyId(); //or any other field that you need to inspect
                    final String iss = (String) claims.get(Claims.ISSUER);

                    if (keyId == null || keyId.isEmpty()) {
                        keyId = DEFAULT_KID;
                    }

                    Environment env = executionContext.getComponent(Environment.class);
                    return parsePublicKey(env.getProperty(String.format(PUBLIC_KEY_PROPERTY, iss, keyId)));
                }
            };

            final Jwt token = Jwts.parser().setSigningKeyResolver(resolver).parse(jwt);
            policyChain.doNext(request, response);
        } catch (Exception e) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized via JWT"));
        }
    }

    private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");

    static RSAPublicKey parsePublicKey(String key) {
        Matcher m = SSH_PUB_KEY.matcher(key);

        if (m.matches()) {
            String alg = m.group(1);
            String encKey = m.group(2);
            //String id = m.group(3);

            if (!"rsa".equalsIgnoreCase(alg)) {
                throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
            }

            return parseSSHPublicKey(encKey);
        }

        return null;
    }

    private static RSAPublicKey parseSSHPublicKey(String encKey) {
        final byte[] PREFIX = new byte[] {0,0,0,7, 's','s','h','-','r','s','a'};
        ByteArrayInputStream in = new ByteArrayInputStream(Codecs.b64Decode(Codecs.utf8Encode(encKey)));

        byte[] prefix = new byte[11];

        try {
            if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
                throw new IllegalArgumentException("SSH key prefix not found");
            }

            BigInteger e = new BigInteger(readBigInteger(in));
            BigInteger n = new BigInteger(readBigInteger(in));

            return createPublicKey(n, e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
        byte[] b = new byte[4];

        if (in.read(b) != 4) {
            throw new IOException("Expected length data as 4 bytes");
        }

        int l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

        b = new byte[l];

        if (in.read(b) != l) {
            throw new IOException("Expected " + l + " key bytes");
        }

        return b;
    }
}
