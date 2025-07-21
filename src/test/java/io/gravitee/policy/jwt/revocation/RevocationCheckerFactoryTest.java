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
package io.gravitee.policy.jwt.revocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.RevocationCheckConfiguration;
import io.vertx.rxjava3.core.Vertx;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCheckerFactoryTest {

    @Mock
    private BaseExecutionContext ctx;

    @Mock
    private Vertx vertx;

    @Mock
    private Configuration configuration;

    @Test
    void should_create_revocation_check_without_cache_when_configuration_invalid() {
        RevocationCheckConfiguration config = new RevocationCheckConfiguration(true, null, null, null, null, null, false, false, null);

        RevocationChecker result = RevocationCheckerFactory.create(config, ctx);

        assertThat(result).isNotNull();
        verifyNoInteractions(ctx);
        verifyNoInteractions(vertx);
    }

    @Test
    void should_create_content_retriever_with_correct_parameters() {
        when(ctx.getComponent(Vertx.class)).thenReturn(vertx);
        when(ctx.getComponent(Configuration.class)).thenReturn(configuration);

        RevocationCheckConfiguration config = new RevocationCheckConfiguration(
            true,
            null,
            "https://url.com",
            null,
            null,
            null,
            false,
            false,
            null
        );

        RevocationChecker result = RevocationCheckerFactory.create(config, ctx);

        assertThat(result).isNotNull();
        verify(ctx).getComponent(Vertx.class);
        verify(ctx).getComponent(Configuration.class);
    }
}
