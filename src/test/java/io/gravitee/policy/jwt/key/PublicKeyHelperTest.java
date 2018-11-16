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
package io.gravitee.policy.jwt.key;

import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.RSAPublicKey;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class PublicKeyHelperTest {

    @Test
    public void shouldGetPublicKey_completeSshRsa() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1 brasseld@gmail.com");

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void shouldGetPublicKey2_noAlg() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey("AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1 brasseld@gmail.com");

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void shouldGetPublicKey2_noAlgAndMail() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey("AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1");

        Assert.assertNotNull(publicKey);
    }
}
