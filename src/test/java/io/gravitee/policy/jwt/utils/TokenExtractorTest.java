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

import static org.mockito.Mockito.when;

import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.context.kafka.KafkaConnectionContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import org.apache.kafka.common.security.auth.SaslExtensions;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TokenExtractorTest {

    @Nested
    class WithHttpExecutionContext {

        @Mock
        private HttpPlainRequest request;

        @Mock
        private HttpPlainExecutionContext ctx;

        @Test
        void should_not_extract_with__no_authorization_header() {
            when(request.headers()).thenReturn(HttpHeaders.create());
            when(request.parameters()).thenReturn(new LinkedMultiValueMap<>());

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isEmpty());
        }

        @Test
        void should_not_extract_with_unknown_authorization_header() {
            String jwt = "dummy-token";

            HttpHeaders headers = HttpHeaders.create().set("Authorization", "Basic " + jwt);
            when(request.headers()).thenReturn(headers);

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isEmpty());
        }

        @Test
        void should_extract_with_authorization_header_and_empty_bearer() {
            HttpHeaders headers = HttpHeaders.create().set("Authorization", TokenExtractor.BEARER);
            when(request.headers()).thenReturn(headers);

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
        }

        @Test
        void should_extract_with_authorization_header_and_bearer() {
            String jwt = "dummy-token";

            HttpHeaders headers = HttpHeaders.create().set("Authorization", TokenExtractor.BEARER + ' ' + jwt);
            when(request.headers()).thenReturn(headers);

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
            Assertions.assertEquals(jwt, token.get());
        }

        @Test
        void should_extract_from_insensitive_header() {
            String jwt = "dummy-token";

            HttpHeaders headers = HttpHeaders.create().set("Authorization", "bearer " + jwt);
            when(request.headers()).thenReturn(headers);

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
            Assertions.assertEquals(jwt, token.get());
        }

        @Test
        void should_extract_from_query_parameter() {
            String jwt = "dummy-token";

            when(request.headers()).thenReturn(HttpHeaders.create());

            LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(TokenExtractor.ACCESS_TOKEN, jwt);
            when(request.parameters()).thenReturn(parameters);

            when(ctx.request()).thenReturn(request);

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
            Assertions.assertEquals(jwt, token.get());
        }
    }

    @Nested
    class WithKafkaConnectionContext {

        @Mock
        private KafkaConnectionContext ctx;

        @Test
        void should_not_extract_with__no_callback() {
            when(ctx.callbacks()).thenReturn(new Callback[] {});

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isEmpty());
        }

        @Test
        void should_extract_with_OAuthBearerValidatorCallback() {
            String jwt = "dummy-token";

            OAuthBearerValidatorCallback oauthCallback = new OAuthBearerValidatorCallback(jwt);
            when(ctx.callbacks()).thenReturn(new Callback[] { oauthCallback });

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
            Assertions.assertEquals(jwt, token.get());
        }

        @Test
        void should_extract_with_OAuthBearerExtensionsValidatorCallback() {
            String jwt = "dummy-token";

            OAuthBearerToken oAuthBearerToken = new BasicOAuthBearerToken(
                jwt,
                Set.of(),
                Long.MAX_VALUE,
                "user",
                System.currentTimeMillis()
            );
            OAuthBearerExtensionsValidatorCallback oauthCallback = new OAuthBearerExtensionsValidatorCallback(
                oAuthBearerToken,
                new SaslExtensions(Map.of())
            );
            when(ctx.callbacks()).thenReturn(new Callback[] { oauthCallback });

            Optional<String> token = TokenExtractor.extract(ctx);

            Assertions.assertTrue(token.isPresent());
            Assertions.assertEquals(jwt, token.get());
        }
    }
}
