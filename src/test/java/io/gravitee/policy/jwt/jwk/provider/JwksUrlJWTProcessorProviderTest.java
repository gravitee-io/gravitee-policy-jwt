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

import static io.gravitee.policy.jwt.jwk.provider.DefaultJWTProcessorProvider.ATTR_INTERNAL_RESOLVED_PARAMETER;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.jupiter.api.context.HttpExecutionContext;
import io.gravitee.policy.jwt.alg.Signature;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.gravitee.policy.jwt.jwk.AbstractJWKTest;
import io.gravitee.policy.jwt.jwk.source.ResourceRetriever;
import io.reactivex.rxjava3.core.Single;
import io.reactivex.rxjava3.observers.TestObserver;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class JwksUrlJWTProcessorProviderTest extends AbstractJWKTest {

    protected static final String JWKS_URL = "https://gravitee.io/.well-known/{type}/jwks.json";
    protected static final String MOCK_EXCEPTION = "Mock exception";

    @Mock
    private JWTPolicyConfiguration configuration;

    @Mock
    private HttpExecutionContext ctx;

    @Mock
    private ResourceRetriever resourceRetriever;

    @ParameterizedTest
    @MethodSource("provideRSAParameters")
    void shouldVerifyRSASignature(Integer keySize, Signature signature) throws Exception {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSet jwkSet = generateJWKSConfiguration(keySize, signature, 1, 1);
        final RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        final String jwt = generateJWT(rsaKey, "gravitee0.io", "key0");

        when(resourceRetriever.retrieve(jwksUrl))
            .thenReturn(Single.just(new Resource(jwkSet.toPublicJWKSet().toString(), "application/json")));
        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)).thenReturn(jwksUrl);

        final JwksUrlJWTProcessorProvider cut = new JwksUrlJWTProcessorProvider(configuration);
        ReflectionTestUtils.setField(cut, "resourceRetriever", resourceRetriever);
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
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSet jwkSet = generateJWKSConfiguration(keySize, signature, 2, 2);
        final RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(jwkSet.getKeys().size() - 1);
        final String jwt = generateJWT(rsaKey, "gravitee1.io", "key1");

        when(resourceRetriever.retrieve(jwksUrl))
            .thenReturn(Single.just(new Resource(jwkSet.toPublicJWKSet().toString(), "application/json")));
        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)).thenReturn(jwksUrl);

        final JwksUrlJWTProcessorProvider cut = new JwksUrlJWTProcessorProvider(configuration);
        ReflectionTestUtils.setField(cut, "resourceRetriever", resourceRetriever);
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
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSet jwkSet = generateJWKSHMACConfiguration(keySize, signature, 2, 2);
        final OctetSequenceKey hmacKey = (OctetSequenceKey) jwkSet.getKeys().get(jwkSet.getKeys().size() - 1);
        final String jwt = generateJWT(hmacKey.toByteArray(), signature.getAlg(), "gravitee1.io", "key1");

        when(resourceRetriever.retrieve(jwksUrl)).thenReturn(Single.just(new Resource(jwkSet.toString(false), "application/json")));
        when(configuration.getSignature()).thenReturn(signature);
        when(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)).thenReturn(jwksUrl);

        final JwksUrlJWTProcessorProvider cut = new JwksUrlJWTProcessorProvider(configuration);
        ReflectionTestUtils.setField(cut, "resourceRetriever", resourceRetriever);
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
    void shouldNotValidateWhenInvalidKeyId() throws Exception {
        final String jwksUrl = JWKS_URL.replace("{type}", UUID.randomUUID().toString());
        final JWKSet jwkSet = generateJWKSConfiguration(2048, Signature.RSA_RS256, 1, 1);
        final RSAKey rsaKey = (RSAKey) jwkSet.getKeys().get(0);
        final String jwt = generateJWT(rsaKey, "gravitee1.io", "invalid");

        when(resourceRetriever.retrieve(jwksUrl))
            .thenReturn(Single.just(new Resource(jwkSet.toPublicJWKSet().toString(), "application/json")));
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)).thenReturn(jwksUrl);

        final JwksUrlJWTProcessorProvider cut = new JwksUrlJWTProcessorProvider(configuration);
        ReflectionTestUtils.setField(cut, "resourceRetriever", resourceRetriever);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertComplete();
        obs.assertValue(jwtProcessor -> {
            assertTrue(jwtProcessor instanceof DefaultJWTProcessor);
            assertThrows(BadJOSEException.class, () -> jwtProcessor.process(jwt, null));

            return true;
        });
        obs.assertNoErrors();
    }

    @Test
    void shouldErrorWhenErrorOccurredWhenRetrievingJWKS() throws Exception {
        when(resourceRetriever.retrieve(JWKS_URL)).thenReturn(Single.error(new RuntimeException(MOCK_EXCEPTION)));
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(ctx.getInternalAttribute(ATTR_INTERNAL_RESOLVED_PARAMETER)).thenReturn(JWKS_URL);

        final JwksUrlJWTProcessorProvider cut = new JwksUrlJWTProcessorProvider(configuration);
        ReflectionTestUtils.setField(cut, "resourceRetriever", resourceRetriever);
        final TestObserver<JWTProcessor<SecurityContext>> obs = cut.provide(ctx).test();

        obs.assertError(throwable -> MOCK_EXCEPTION.equals(throwable.getMessage()));
    }

    private JWKSet generateJWKSConfiguration(Integer keySize, Signature signature, int nbIssuers, int nbSecretsPerIssuer) {
        final List<JWK> rsaKeys = new ArrayList<>();
        KeyPair keyPair;
        RSAKey rsaKey;

        for (int i = 0; i < nbIssuers; i++) {
            for (int j = 0; j < nbSecretsPerIssuer; j++) {
                keyPair = generateKeyPair(keySize, signature.getAlg());
                rsaKey =
                    new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey(keyPair.getPrivate())
                        .keyID("key" + j)
                        .algorithm(signature.getAlg())
                        .build();

                rsaKeys.add(rsaKey);
            }
        }

        return new JWKSet(rsaKeys);
    }

    private JWKSet generateJWKSHMACConfiguration(Integer keySize, Signature signature, int nbIssuers, int nbSecretsPerIssuer) {
        final List<JWK> jwks = new ArrayList<>();
        SecureRandom random;
        byte[] sharedSecret;

        for (int i = 0; i < nbIssuers; i++) {
            for (int j = 0; j < nbSecretsPerIssuer; j++) {
                random = new SecureRandom();
                sharedSecret = new byte[keySize];
                random.nextBytes(sharedSecret);

                jwks.add(new OctetSequenceKey.Builder(sharedSecret).algorithm(signature.getAlg()).keyID("key" + j).build());
            }
        }

        return new JWKSet(jwks);
    }
}
