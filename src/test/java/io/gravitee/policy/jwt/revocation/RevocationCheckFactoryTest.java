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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.jwt.configuration.JWTPolicyConfiguration;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.RequestOptions;
import io.vertx.rxjava3.core.Vertx;
import io.vertx.rxjava3.core.http.HttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevocationCheckFactoryTest {

    @Mock
    private BaseExecutionContext ctx;

    @Mock
    private Vertx vertx;

    @Mock
    private Configuration configuration;

    @Mock
    private JWTPolicyConfiguration.RevocationCheck revocationCheckConfig;

    private RevocationCheckFactory factory;

    @BeforeEach
    void setUp() {
        factory = new RevocationCheckFactory();
    }

    @Test
    void shouldCreateRevocationCheckWithoutCacheWhenConfigurationInvalid() {
        when(revocationCheckConfig.isValid()).thenReturn(false);

        RevocationCheck result = factory.create(revocationCheckConfig, ctx);

        assertThat(result).isNotNull();
        verify(revocationCheckConfig).isValid();
        verifyNoMoreInteractions(revocationCheckConfig);
        verify(ctx, never()).getComponent(Vertx.class);
        verify(ctx, never()).getComponent(Configuration.class);
    }

    @Test
    void shouldCreateContentRetrieverWithCorrectParameters() {
        HttpClient httpClient = mock(HttpClient.class);
        when(vertx.createHttpClient(any(HttpClientOptions.class))).thenReturn(httpClient);
        when(httpClient.rxRequest(any(RequestOptions.class))).thenReturn(Single.never());

        when(ctx.getComponent(Vertx.class)).thenReturn(vertx);
        when(ctx.getComponent(Configuration.class)).thenReturn(configuration);
        when(revocationCheckConfig.isValid()).thenReturn(true);
        when(revocationCheckConfig.normalized()).thenReturn(revocationCheckConfig);
        when(revocationCheckConfig.getRevocationListUrl()).thenReturn("http://localhost:8080/revocation-list");
        when(revocationCheckConfig.getRefreshInterval()).thenReturn(300);
        when(revocationCheckConfig.getConnectTimeout()).thenReturn(5000);
        when(revocationCheckConfig.getRequestTimeout()).thenReturn(10000L);
        when(revocationCheckConfig.isUseSystemProxy()).thenReturn(true);
        when(revocationCheckConfig.isFollowRedirects()).thenReturn(true);
        when(revocationCheckConfig.getAuth()).thenReturn(null);

        RevocationCheck result = factory.create(revocationCheckConfig, ctx);

        assertThat(result).isNotNull();
        verify(revocationCheckConfig).getRevocationListUrl();
        verify(revocationCheckConfig).getRefreshInterval();
        verify(revocationCheckConfig).getConnectTimeout();
        verify(revocationCheckConfig).getRequestTimeout();
        verify(revocationCheckConfig).isUseSystemProxy();
        verify(revocationCheckConfig).isFollowRedirects();
        verify(revocationCheckConfig).getAuth();
        verify(vertx).createHttpClient(any(HttpClientOptions.class));
    }
}
