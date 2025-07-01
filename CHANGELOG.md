## [6.1.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.3...6.1.4) (2025-07-01)


### Bug Fixes

* bump gravitee-parent ([164afa8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/164afa8b95fa74efbe30f150465848b1346454d6))
* condition `.metrics()` use only if ctx is http ([acd3f04](https://github.com/gravitee-io/gravitee-policy-jwt/commit/acd3f0435de83e8204d722df41dae0fc7bf897ff))

## [6.1.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.2...6.1.3) (2025-06-30)


### Bug Fixes

* condition `.metrics()` use only if ctx is http ([cac9b37](https://github.com/gravitee-io/gravitee-policy-jwt/commit/cac9b37038bf0e19b1b7032d05c4af66385d322a))

## [6.1.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.1...6.1.2) (2025-03-27)


### Bug Fixes

* follow http redirect on v2 api ([ca861ce](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ca861ce0b95acc842933d7e103c2dcf2bc73447b))

## [6.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.0...6.1.1) (2025-03-13)


### Bug Fixes

* Properly resolve property value ([723382d](https://github.com/gravitee-io/gravitee-policy-jwt/commit/723382de91a580d5cf6be5d762ac9965579934f0))

# [6.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0...6.1.0) (2025-03-10)


### Features

* add option to follow http redirects ([a5efe2e](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a5efe2e3d9645a3c039b32f59063c6ccfca6d19d))

# [6.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.2.0...6.0.0) (2024-12-30)


### Bug Fixes

* **deps:** bump apim version ([7999be1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7999be10ad558c09feda4c2446ba72de081afaa5))
* invoke callback and complete on auth failure ([3f64243](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3f64243e2455609057d4b947c11c623c2cefdf07))
* use provided version of nimbus lib ([7063db4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7063db42c55cd6bd8a3021502f0bfaf03ce02f12))


### Code Refactoring

* use new HttpSecurityPolicy and BaseExecutionContext interface ([8f6270f](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8f6270f8f22e06c972c141d12c28433b5da2f34e))


### Features

* implement kafka security policy ([f1db2f1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/f1db2f1818a8cc60f8dfeace66a2c5a8d57bd600))
* set a max value for kafka token lifetime ([9195623](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9195623d3e7d3a0f2863ad0837f8cfcdb6295ea3))
* support custom token type header ([d08e658](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d08e65834b2eaf111dc9bdeeaa54223160a10fa4))


### BREAKING CHANGES

* requires APIM 4.6+

# [6.0.0-alpha.5](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.4...6.0.0-alpha.5) (2024-12-30)


### Bug Fixes

* **deps:** bump apim version ([7999be1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7999be10ad558c09feda4c2446ba72de081afaa5))


### Features

* support custom token type header ([47e1918](https://github.com/gravitee-io/gravitee-policy-jwt/commit/47e19180b7cf95ca01172e0a844171c2a6ae141a))

# [6.0.0-alpha.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.3...6.0.0-alpha.4) (2024-11-29)


### Features

* set a max value for kafka token lifetime ([9195623](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9195623d3e7d3a0f2863ad0837f8cfcdb6295ea3))

# [6.0.0-alpha.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.2...6.0.0-alpha.3) (2024-11-22)


### Bug Fixes

* invoke callback and complete on auth failure ([3f64243](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3f64243e2455609057d4b947c11c623c2cefdf07))

# [6.0.0-alpha.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.1...6.0.0-alpha.2) (2024-11-13)


### Features

* support custom token type header ([d08e658](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d08e65834b2eaf111dc9bdeeaa54223160a10fa4))

# [6.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.1.0...6.0.0-alpha.1) (2024-11-12)


### Bug Fixes

* use provided version of nimbus lib ([7063db4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7063db42c55cd6bd8a3021502f0bfaf03ce02f12))


### Code Refactoring

* use new HttpSecurityPolicy and BaseExecutionContext interface ([8f6270f](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8f6270f8f22e06c972c141d12c28433b5da2f34e))


### Features

* implement kafka security policy ([f1db2f1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/f1db2f1818a8cc60f8dfeace66a2c5a8d57bd600))


### BREAKING CHANGES

* requires APIM 4.6+

# [5.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.1.0...5.2.0) (2024-11-07)

### Features

* support custom token type header ([47e1918](https://github.com/gravitee-io/gravitee-policy-jwt/commit/47e19180b7cf95ca01172e0a844171c2a6ae141a))

# [5.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.0.0...5.1.0) (2024-10-25)


### Features

* make jwks url timeouts configurable ([9e45980](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9e459800127bf93940f5b5c8494bab13250375e6))

# [5.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.5...5.0.0) (2024-07-31)


### chore

* **deps:** bump dependencies ([124d55a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/124d55abdf053b47f00a41addcd0c661232c061a))


### BREAKING CHANGES

* **deps:** require APIM 4.4.x

## [4.1.5](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.4...4.1.5) (2024-07-31)


### Bug Fixes

* Revert do not use 4.1.4 with version lower or equal to 4.3.x => 4.1.x ([67d2208](https://github.com/gravitee-io/gravitee-policy-jwt/commit/67d22089b2601ddea8de0eaaac7c71b9dc9cd45c))

## [4.1.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.3...4.1.4) (2024-07-30)


### Bug Fixes

* **dependency:** VertxProxyOptionsUtils was moved to gravitee-node ([12f4e2a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/12f4e2a29670a5cc588c06dd92aae5b73a998d29))

## [4.1.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.2...4.1.3) (2024-06-26)


### Bug Fixes

* **gateway-keys:** when using gateway keys resolverParameter should be ignored ([ce04d1b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ce04d1b6af1dab317830311cbdf184ef5f7967ac))

## [4.1.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.1...4.1.2) (2024-03-07)


### Bug Fixes

* **deps:** update bcprov-jdk15on to bcprov-jdk18on and bcpkix-jdk15on to bcpkix-jdk18on ([337dee2](https://github.com/gravitee-io/gravitee-policy-jwt/commit/337dee2e04e6eb747dca93752c650598933865a1))

## [4.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.0...4.1.1) (2023-09-12)


### Bug Fixes

* bump gravitee common version ([5040027](https://github.com/gravitee-io/gravitee-policy-jwt/commit/504002776dc9d0e80e448d498c5a90033c6ca794))

# [4.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.1...4.1.0) (2023-09-05)


### Features

* add new option allowing to check confirmation method ([3db2346](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3db23464134d46d806308271f5090e19278e050c)), closes [x5t#S256](https://github.com/x5t/issues/S256)

## [4.0.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0...4.0.1) (2023-07-20)


### Bug Fixes

* update policy description ([214983d](https://github.com/gravitee-io/gravitee-policy-jwt/commit/214983d64b5a50bfcefeb2291f958951072a770d))

# [4.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.2.0...4.0.0) (2023-07-18)


### Bug Fixes

* bump `gravitee-parent` to fix release on Maven Central ([e16c40a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/e16c40a22ca97828c7803dfbda6dd2d0e2819f3c))
* bump dependencies versions ([0d3e4dd](https://github.com/gravitee-io/gravitee-policy-jwt/commit/0d3e4dd782cb13bb4b6f4c6b0f56d5ad9444a6b5))
* properly handle token extraction ([702458b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/702458bb45c1fc083977e5b5f32bb036e5560062))
* simplify unauthorized message ([087383c](https://github.com/gravitee-io/gravitee-policy-jwt/commit/087383ce88e4c1fc810479b3506e7e7b849647f2))


### chore

* **deps:** update gravitee-parent ([7f93871](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7f93871cd891085da1763eb12dd5f92b7673497e))


### BREAKING CHANGES

* **deps:** require Java17
* use apim version 4

# [4.0.0-alpha.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.3...4.0.0-alpha.4) (2023-07-07)


### Bug Fixes

* bump `gravitee-parent` to fix release on Maven Central ([e16c40a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/e16c40a22ca97828c7803dfbda6dd2d0e2819f3c))

# [4.0.0-alpha.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.2...4.0.0-alpha.3) (2023-07-06)


### Bug Fixes

* properly handle token extraction ([702458b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/702458bb45c1fc083977e5b5f32bb036e5560062))

# [4.0.0-alpha.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.1...4.0.0-alpha.2) (2023-07-05)


### Bug Fixes

* simplify unauthorized message ([087383c](https://github.com/gravitee-io/gravitee-policy-jwt/commit/087383ce88e4c1fc810479b3506e7e7b849647f2))

# [4.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.2.0...4.0.0-alpha.1) (2023-07-04)


### Bug Fixes

* bump dependencies versions ([0d3e4dd](https://github.com/gravitee-io/gravitee-policy-jwt/commit/0d3e4dd782cb13bb4b6f4c6b0f56d5ad9444a6b5))


### BREAKING CHANGES

* use apim version 4

# [3.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.1.1...3.2.0) (2023-05-29)


### Features

* provide execution phase in manifest ([92b15d9](https://github.com/gravitee-io/gravitee-policy-jwt/commit/92b15d97862e10dbbc43b421af34735fe2e86b8c))

## [3.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.1.0...3.1.1) (2023-04-18)


### Bug Fixes

* clean schema-form to make it compatible with gio-form-json-schema component ([dfd64f3](https://github.com/gravitee-io/gravitee-policy-jwt/commit/dfd64f358c5e71a47eb74414ba82885b9fcb33e3))

# [3.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.0...3.1.0) (2023-03-17)


### Bug Fixes

* bump version of gateway api ([d062a55](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d062a557795f4e3b279351599e1c591a51d25b1b))
* **deps:** upgrade gravitee-bom & alpha version ([b2da107](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b2da107c0998bd54be9294ff134e59f7cdd853db))


### Features

* rename 'jupiter' package in 'reactive' ([2af6540](https://github.com/gravitee-io/gravitee-policy-jwt/commit/2af6540ff562c27ea64670051ef4f667eef12d42))

# [3.1.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.1-alpha.1...3.1.0-alpha.1) (2023-03-13)


### Features

* rename 'jupiter' package in 'reactive' ([aaae6c5](https://github.com/gravitee-io/gravitee-policy-jwt/commit/aaae6c5802e4b1a652d630f398adcdd2c34f2b58))

## [3.0.1-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.0...3.0.1-alpha.1) (2023-02-02)


### Bug Fixes

* bump version of gateway api ([ae0bdad](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ae0bdadaba7adc9c1469d7a2c2d48f64237ff170))

# [3.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.4.0...3.0.0) (2022-12-09)


### chore

* bump to rxJava3 ([a69c5b4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a69c5b47b3a0e846d27e00382b8989856755cfdc))


### BREAKING CHANGES

* rxJava3 required

# [3.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.4.0...3.0.0-alpha.1) (2022-10-19)


### chore

* bump to rxJava3 ([a69c5b4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a69c5b47b3a0e846d27e00382b8989856755cfdc))


### BREAKING CHANGES

* rxJava3 required

# [2.4.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.3.0...2.4.0) (2022-09-05)


### Bug Fixes

* plan selection for v3 engine ([82d4a49](https://github.com/gravitee-io/gravitee-policy-jwt/commit/82d4a49c89ba418d24e7b6a90ad4f641a204dcab))


### Features

* improve execution context structure ([1b5a166](https://github.com/gravitee-io/gravitee-policy-jwt/commit/1b5a166a252011ee1066ad61901c7c9d5938b586)), closes [gravitee-io/issues#8386](https://github.com/gravitee-io/issues/issues/8386)

# [2.3.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.2.0...2.3.0) (2022-08-16)


### Features

* migrate to the new version of Jupiter's SecurityPolicy ([b384ee8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b384ee8047ac25361a3df9ba23683905e301d96b))

# [2.3.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.2.0...2.3.0) (2022-08-16)


### Features

* migrate to the new version of Jupiter's SecurityPolicy ([b384ee8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b384ee8047ac25361a3df9ba23683905e301d96b))

# [2.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.1.1...2.2.0) (2022-08-08)


### Features

* **sme:** update security policy to be compatible with async reactor ([50f6426](https://github.com/gravitee-io/gravitee-policy-jwt/commit/50f64262a1e81eee3b8774e7a5069583ec87a7ee))

## [2.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.1.0...2.1.1) (2022-06-30)


### Bug Fixes

* **jupiter:** support plain text hmac key ([8ec1fa9](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8ec1fa91f9919ba502532995a6f12afc4b46a9e6)), closes [gravitee-io/issues#7947](https://github.com/gravitee-io/issues/issues/7947)

# [2.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.0.0...2.1.0) (2022-06-10)


### Features

* **jupiter:** move to Jupiter SecurityPolicy ([24bbdac](https://github.com/gravitee-io/gravitee-policy-jwt/commit/24bbdacdc56d9063c3744d9858e2c2dff02c7397))

# [2.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/1.22.0...2.0.0) (2022-05-24)


### Code Refactoring

* use common vertx proxy options factory ([92d2da5](https://github.com/gravitee-io/gravitee-policy-jwt/commit/92d2da534641726ace500abc91db718941208461))


### BREAKING CHANGES

* this version requires APIM in version 3.18 and upper

# [1.22.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/1.21.0...1.22.0) (2022-01-21)


### Features

* **headers:** Internal rework and introduce HTTP Headers API ([28ea9c6](https://github.com/gravitee-io/gravitee-policy-jwt/commit/28ea9c600f08cf76d1aa0df463c418a66cbc4753)), closes [gravitee-io/issues#6772](https://github.com/gravitee-io/issues/issues/6772)
