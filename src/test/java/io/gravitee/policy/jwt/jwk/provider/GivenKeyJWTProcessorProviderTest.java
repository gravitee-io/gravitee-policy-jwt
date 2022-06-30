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
package io.gravitee.policy.jwt.jwk.provider;

import static io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider.RESOLVED_PARAMETER;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.jupiter.api.context.RequestExecutionContext;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.AbstractJWKTest;
import io.reactivex.observers.TestObserver;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class GivenKeyJWTProcessorProviderTest extends AbstractJWKTest {

    @Mock
    private JWTPolicyConfiguration configuration;

    @Mock
    private RequestExecutionContext ctx;

    @ParameterizedTest
    @MethodSource("provideRSAParameters")
    void shouldVerifyRSASignatureWithSSHPublicKeyFormat(Integer keySize, Signature signature) throws Exception {
        final KeyPair keyPair = generateKeyPair(keySize, signature.getAlg());
        final String sshPublicKey = toSSHPublicKeyFormat(keyPair.getPublic());
        final RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey(keyPair.getPrivate())
            .algorithm(signature.getAlg())
            .build();

        final String jwt = generateJWT(rsaKey, "gravitee.io", "key1");

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(RESOLVED_PARAMETER)).thenReturn(sshPublicKey);

        final GivenKeyJWTProcessorProvider cut = new GivenKeyJWTProcessorProvider(configuration);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            assertNotNull(jwtProcessor.process(jwt, null));

            return true;
        });
        obs.assertNoErrors();
    }

    @ParameterizedTest
    @MethodSource("provideRSAParameters")
    void shouldVerifyRSASignatureWithPEMFormat(Integer keySize, Signature signature) throws Exception {
        final KeyPair keyPair = generateKeyPair(keySize, signature.getAlg());
        final String pemPublicKey = toPEMFormat(keyPair.getPublic());
        final RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey(keyPair.getPrivate())
            .algorithm(signature.getAlg())
            .build();

        final String jwt = generateJWT(rsaKey, "gravitee.io", "key1");

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(RESOLVED_PARAMETER)).thenReturn(pemPublicKey);

        final GivenKeyJWTProcessorProvider cut = new GivenKeyJWTProcessorProvider(configuration);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            assertNotNull(jwtProcessor.process(jwt, null));

            return true;
        });
        obs.assertNoErrors();
    }

    @ParameterizedTest
    @MethodSource("provideHMACWithOptionalBase64Parameters")
    void shouldVerifyHMACSignature(Integer keySize, Signature signature, boolean encodeBase64) throws Exception {
        final byte[] sharedSecret = generateHMACKey(keySize);
        final String jwt = generateJWT(sharedSecret, signature.getAlg(), "gravitee0.io", "key0");

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(RESOLVED_PARAMETER))
            .thenReturn(encodeBase64 ? Base64.getEncoder().encodeToString(sharedSecret) : new String(sharedSecret));

        final GivenKeyJWTProcessorProvider cut = new GivenKeyJWTProcessorProvider(configuration);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            assertNotNull(jwtProcessor.process(jwt, null));

            return true;
        });
        obs.assertNoErrors();
    }

    @Test
    void shouldIgnoreAndLogInvalidKey() {
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(ctx.getInternalAttribute(RESOLVED_PARAMETER)).thenReturn("invalid");

        final GivenKeyJWTProcessorProvider cut = new GivenKeyJWTProcessorProvider(configuration);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            return true;
        });
        obs.assertNoErrors();
    }
}
