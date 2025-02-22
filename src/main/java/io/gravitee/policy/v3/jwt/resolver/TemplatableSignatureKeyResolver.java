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
package io.gravitee.policy.v3.jwt.resolver;

import io.gravitee.el.TemplateEngine;
import java.text.ParseException;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class TemplatableSignatureKeyResolver implements SignatureKeyResolver {

    private final TemplateEngine templateEngine;
    private final SignatureKeyResolver keyResolver;

    public TemplatableSignatureKeyResolver(TemplateEngine templateEngine, SignatureKeyResolver keyResolver) {
        this.templateEngine = templateEngine;
        this.keyResolver = keyResolver;
    }

    @Override
    public String resolve() throws ParseException {
        String publicKey = keyResolver.resolve();
        return templateEngine.getValue(publicKey, String.class);
    }
}
