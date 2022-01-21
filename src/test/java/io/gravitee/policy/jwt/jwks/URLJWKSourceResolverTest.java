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
package io.gravitee.policy.jwt.jwks;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.util.Resource;
import io.gravitee.el.TemplateEngine;
import io.gravitee.policy.jwt.jwks.retriever.ResourceRetriever;
import java.net.MalformedURLException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class URLJWKSourceResolverTest {

    private static final String VALID_URL = "http://localhost:8082/myurl";

    private URLJWKSourceResolver urljwkSourceResolver;

    @Mock
    private TemplateEngine templateEngine;

    @Mock
    private ResourceRetriever resourceRetriever;

    @Before
    public void setUp() throws MalformedURLException {
        when(templateEngine.getValue("valid_url", String.class)).thenReturn(VALID_URL);
        urljwkSourceResolver = new URLJWKSourceResolver(templateEngine, "valid_url", resourceRetriever);
    }

    @Test(expected = MalformedURLException.class)
    public void builder_should_throw_MalformedURLException_when_invalid_url() throws MalformedURLException {
        when(templateEngine.getValue("invalid_url", String.class)).thenReturn("this_url.is_invalid");

        new URLJWKSourceResolver(templateEngine, "invalid_url", mock(ResourceRetriever.class));
    }

    @Test
    public void resolve_should_return_cached_value_when_not_expired() throws ExecutionException, InterruptedException {
        JWKSource cachedJwks = mock(JWKSource.class);
        CachedJWKSource cachedJWKSource = new CachedJWKSource(cachedJwks);

        URLJWKSourceResolver urlJWKSourceResolverSpy = spy(urljwkSourceResolver);
        doReturn(false).when(urlJWKSourceResolverSpy).isCacheExpired(cachedJWKSource);

        urlJWKSourceResolverSpy.cache.put(VALID_URL, cachedJWKSource);

        CompletableFuture<JWKSource> future = urlJWKSourceResolverSpy.resolve();

        assertEquals(cachedJwks, future.get());
        verifyNoInteractions(resourceRetriever);
    }

    @Test
    public void resolve_should_call_retriever_when_cached_value_is_expired() {
        JWKSource cachedJwks = mock(JWKSource.class);
        CachedJWKSource cachedJWKSource = new CachedJWKSource(cachedJwks);

        URLJWKSourceResolver urlJWKSourceResolverSpy = spy(urljwkSourceResolver);
        doReturn(true).when(urlJWKSourceResolverSpy).isCacheExpired(cachedJWKSource);

        urlJWKSourceResolverSpy.cache.put(VALID_URL, cachedJWKSource);

        when(resourceRetriever.retrieve(any())).thenReturn(CompletableFuture.completedFuture(mock(Resource.class)));

        urlJWKSourceResolverSpy.resolve();

        verify(resourceRetriever, times(1)).retrieve(argThat(url -> VALID_URL.equals(url.toString())));
    }

    @Test
    public void resolve_should_call_retriever_when_no_cached_value() {
        when(resourceRetriever.retrieve(any())).thenReturn(CompletableFuture.completedFuture(mock(Resource.class)));

        urljwkSourceResolver.resolve();

        verify(resourceRetriever, times(1)).retrieve(argThat(url -> VALID_URL.equals(url.toString())));
    }

    @Test
    public void resolve_should_return_old_cached_value_when_retriever_fails() throws ExecutionException, InterruptedException {
        JWKSource cachedJwks = mock(JWKSource.class);
        CachedJWKSource cachedJWKSource = new CachedJWKSource(cachedJwks);

        URLJWKSourceResolver urlJWKSourceResolverSpy = spy(urljwkSourceResolver);
        doReturn(true).when(urlJWKSourceResolverSpy).isCacheExpired(cachedJWKSource);

        urlJWKSourceResolverSpy.cache.put(VALID_URL, cachedJWKSource);

        when(resourceRetriever.retrieve(any())).thenReturn(CompletableFuture.failedFuture(new Exception("retreiving jwks failed")));

        CompletableFuture<JWKSource> resultFuture = urlJWKSourceResolverSpy.resolve();

        assertSame(cachedJwks, resultFuture.get());
    }
}
