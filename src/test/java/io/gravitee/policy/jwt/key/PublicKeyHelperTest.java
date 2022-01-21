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

import java.security.interfaces.RSAPublicKey;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class PublicKeyHelperTest {

    @Test
    public void shouldGetPublicKey_completeSshRsa() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1 brasseld@gmail.com"
        );

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void shouldGetPublicKey2_noAlg() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey(
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1 brasseld@gmail.com"
        );

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void shouldGetPublicKey2_noAlgAndMail() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey(
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQCDUffTA84NNSLgfk2rc3xjWdBqTQBzgHLVSpyG+E4X4t6tgZlSbeh8P3fSeIaNWfclvPubU8Xu93s0iM8cjpC2UhN8f76pf+8rPYOsfSExvsO/8FifowZJOHoLhBhmShncgDfTFdCrk0GLdExp/hKEN0oIMVEFzkLPwoS4Dg9RYITQ1/dUb93n1Llb8Kr//dFD0HsBn+ZNOZL1xH9RtglF1zn//ApE40YqjhnamIDCIYuEtdVubg3I+Eb0xZayrbmfjNbt6lUdtpHxhB2N0pcASbcDA+tGo88wX68AxZzJbZQrh9zPHfH3NlM0sU16yX+1X5zrKWQFvKbE0VQZ2Yy1"
        );

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void shouldGetPublicKey_completeSshRsa_RS384() {
        RSAPublicKey publicKey = PublicKeyHelper.parsePublicKey(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCBKYIaYRQU5eHRNqi09OP/dxY/uqS3+RYUBDMBaQeaCydgxciGWg0ijY+FlkjaIj/dlC4QfNxsglOgZtlZ2oFiQ5sDri0kGcczRbgDkTpg0q9+2W0huFxccCM0YOGuKBN8VZCIQhnRvC4gPHwzOdgNNCJqJc0qbuwN9WEkBt5O5aqLbVS395r9qbHFg76K3TVbPUXLtYr6Cmig9iTePEBiXyS4ZV0JjqvDryNP/nCeWf9oz091Eto3UKPZ4K6h1fsi7F9OdP867/2I+F3y/Gxdwk4GHkpq/mVzzVM3x//xTPYfgTZtDf8triNS3gBn0JbEIk8sSMh5MVA1nnAoEsxQM6WWlYJbLbWT5Q1N5nQKShTTnAamTuUg2o4MPJoozVW7GDYHWLL6zkbwGzjXULeZQVQi0VH7ZXdXjk4FC6DxmrIRE9gZhkFC7YpMk/fUmB7aLsXGkpLxjM/2DEq02ypAFfPcQwR3Oi0S+TKb9DqwjX/sb06C4n7pIaZzxMJn4xc= brasseld@gmail.com"
        );

        Assert.assertNotNull(publicKey);
    }
}
