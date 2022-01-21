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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.key.PublicKeyHelper;
import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.stream.Collectors;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RSACertificateJWTPolicyTest extends JWTPolicyTest {

    protected Signature getSignature() {
        return Signature.RSA_RS256;
    }

    protected JWSSigner getSigner() throws Exception {
        RSAKey rsaKey = new RSAKey.Builder(PublicKeyHelper.parsePublicKey(getPublicKey())).privateKey(getPrivateKey()).build();

        return new RSASSASigner(rsaKey);
    }

    protected String getSignatureKey() throws IOException {
        return getCertificate();
    }

    private String getPublicKey() throws IOException {
        InputStream input = getClass().getClassLoader().getResourceAsStream("id_rsa.pub");
        BufferedReader buffer = new BufferedReader(new InputStreamReader(input));
        return buffer.lines().collect(Collectors.joining("\n"));
    }

    private String getCertificate() throws IOException {
        InputStream input = getClass().getClassLoader().getResourceAsStream("id_rsa.crt");
        BufferedReader buffer = new BufferedReader(new InputStreamReader(input));
        return buffer.lines().collect(Collectors.joining("\n"));
    }

    private PrivateKey getPrivateKey() throws Exception {
        File file = new File(getClass().getClassLoader().getResource("private_key.der").toURI());
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }
}
