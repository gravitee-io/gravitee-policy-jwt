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
package io.gravitee.policy.jwt.jwk.provider;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.reactivex.rxjava3.core.Maybe;

/**
 * {@link JWTProcessor} provider allowing to provide an appropriate instance of {@link JWTProcessor} depending on the execution context.
 *
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public interface JWTProcessorProvider {
    /**
     * Provides an adequate processor to use, depending on the request context.
     * It is left to the implementation to decide whether to create an instance on each resolution or cache it for subsequent reuses.
     *
     * @param ctx the current execution context.
     * @return a {@link Maybe} containing an {@link JWTProcessor}.
     */
    Maybe<JWTProcessor<SecurityContext>> provide(final BaseExecutionContext ctx);
}
