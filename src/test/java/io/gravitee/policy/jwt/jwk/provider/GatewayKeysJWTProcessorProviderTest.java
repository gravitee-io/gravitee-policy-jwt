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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

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
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.mock.env.MockEnvironment;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class GatewayKeysJWTProcessorProviderTest extends AbstractJWKTest {

    @Mock
    private JWTPolicyConfiguration configuration;

    @Mock
    private RequestExecutionContext ctx;

    private MockEnvironment environment;

    @BeforeEach
    void init() {
        environment = new MockEnvironment();
    }

    @ParameterizedTest
    @MethodSource("provideRSAParameters")
    void shouldVerifyRSASignature(Integer keySize, Signature signature) throws Exception {
        final RSAKey rsaKey = generateRSAConfiguration(keySize, signature, 1, 1).get(0);
        final String jwt = generateJWT(rsaKey, "gravitee0.io", "key0");

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
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
    void shouldVerifyWithMultipleIssuersAndMultipleRSAKeys(Integer keySize, Signature signature) throws Exception {
        List<RSAKey> rsaKeys = generateRSAConfiguration(keySize, signature, 2, 2);

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        final String jwt = generateJWT(rsaKeys.get(rsaKeys.size() - 1), "gravitee1.io", "key1");
        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
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
    void shouldVerifyRSASignatureAndIgnoreKeyId(Integer keySize, Signature signature) throws Exception {
        final RSAKey rsaKey = generateRSAConfiguration(keySize, signature, 1, 1).get(0);
        final String jwt = generateJWT(rsaKey, "gravitee0.io", "KeyShouldBeIgnored");

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
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
    @MethodSource("provideHMACParameters")
    void shouldVerifyHMACSignature(Integer keySize, Signature signature) throws Exception {
        final byte[] sharedSecret = generateHMACConfiguration(keySize, 2, 1).get(0);
        final String jwt = generateJWT(sharedSecret, signature.getAlg(), "gravitee0.io", "key0");

        environment.withProperty("policy.jwt.issuer.gravitee.io.key1", Base64.getEncoder().encodeToString(sharedSecret));
        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
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
    @MethodSource("provideHMACParameters")
    void shouldVerifyWithMultipleIssuersAndMultipleHMACKeys(Integer keySize, Signature signature) throws Exception {
        List<byte[]> sharedSecrets = generateHMACConfiguration(keySize, 5, 2);

        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        final String jwt = generateJWT(sharedSecrets.get(sharedSecrets.size() - 1), signature.getAlg(), "gravitee4.io", "key1");
        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
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
        when(ctx.getComponent(ConfigurableEnvironment.class)).thenReturn(environment);

        environment.withProperty("policy.jwt.issuer.gravitee.io.key", "invalid");

        final GatewayKeysJWTProcessorProvider cut = new GatewayKeysJWTProcessorProvider(configuration);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            return true;
        });
        obs.assertNoErrors();
    }

    private List<RSAKey> generateRSAConfiguration(Integer keySize, Signature signature, int nbIssuers, int nbSecretsPerIssuer) {
        final List<RSAKey> rsaKeys = new ArrayList<>();
        KeyPair keyPair;
        String sshPublicKey;
        RSAKey rsaKey;

        for (int i = 0; i < nbIssuers; i++) {
            for (int j = 0; j < nbSecretsPerIssuer; j++) {
                keyPair = generateKeyPair(keySize, signature.getAlg());
                sshPublicKey = toSSHPublicKeyFormat(keyPair.getPublic());
                rsaKey =
                    new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey(keyPair.getPrivate())
                        .algorithm(signature.getAlg())
                        .build();

                environment.withProperty("policy.jwt.issuer.gravitee" + i + ".io.key" + j, sshPublicKey);
                rsaKeys.add(rsaKey);
            }
        }

        return rsaKeys;
    }

    private List<byte[]> generateHMACConfiguration(Integer keySize, int nbIssuers, int nbSecretsPerIssuer) {
        List<byte[]> sharedSecrets = new ArrayList<>();
        SecureRandom random;
        byte[] sharedSecret;

        for (int i = 0; i < nbIssuers; i++) {
            for (int j = 0; j < nbSecretsPerIssuer; j++) {
                random = new SecureRandom();
                sharedSecret = new byte[keySize];
                random.nextBytes(sharedSecret);

                environment.withProperty(
                    "policy.jwt.issuer.gravitee" + i + ".io.key" + j,
                    Base64.getEncoder().encodeToString(sharedSecret)
                );

                sharedSecrets.add(sharedSecret);
            }
        }
        return sharedSecrets;
    }
}
