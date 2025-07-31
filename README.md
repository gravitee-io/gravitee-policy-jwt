
<!-- GENERATED CODE - DO NOT ALTER THIS OR THE FOLLOWING LINES -->
# JSON Web Tokens

[![Gravitee.io](https://img.shields.io/static/v1?label=Available%20at&message=Gravitee.io&color=1EC9D2)](https://download.gravitee.io/#graviteeio-apim/plugins/policies/gravitee-policy-jwt/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/gravitee-io/gravitee-policy-jwt/blob/master/LICENSE.txt)
[![Releases](https://img.shields.io/badge/semantic--release-conventional%20commits-e10079?logo=semantic-release)](https://github.com/gravitee-io/gravitee-policy-jwt/releases)
[![CircleCI](https://circleci.com/gh/gravitee-io/gravitee-policy-jwt.svg?style=svg)](https://circleci.com/gh/gravitee-io/gravitee-policy-jwt)

## Overview
You can use the `jwt` policy to validate the token signature and expiration date before sending the API call to the target backend.

Some authorization servers use OAuth2 protocol to provide access tokens. These access token can be in JWS/JWT format. For the RFC standards, see:

- JWS (JSON Web Signature) standard RFC: https://tools.ietf.org/html/rfc7515

- JWT (JSON Web Token) standard RFC: (https://tools.ietf.org/html/rfc7519

A JWT is composed of three parts: a header, a payload and a signature.
You can see some examples here: http://jwt.io.

- The header contains attributes indicating the algorithm used to sign the token.

- The payload contains some information inserted by the AS (Authorization Server), such as the expiration date and UID of the user.

Both the header and payload are encoded with Base64, so anyone can read the content.

- The third and last part is the signature (for more details, see the RFC).



## Usage
The policy will inspect the JWT:

- Header to extract the key id (`kid` attribute) of the public key. If no key id is found then it uses the `x5t` field.
    - If `kid` is present and no key corresponding is found, the token is rejected.
    - If `kid` is missing and no key corresponding to `x5t` is found, the token is rejected.
- Claims (payload) to extract the issuer (`iss` attribute)

Using these two values, the gateway can retrieve the corresponding public key.

Regarding the client_id, the standard behavior is to read it from the `azp` claim, then if not found in the `aud` claim and finally in the `client_id` claim.
You can override this behavior by providing a custom `clientIdClaim` in the configuration.

### Attributes

| Name | Description |
|------|-------------|
| jwt.token | JWT token extracted from the `Authorization` HTTP header |
| jwt.claims | A map of claims registered in the JWT token body, used for extracting data from it. Only if `extractClaims` is enabled in the policy configuration. |

#### Example

Given the following JWT claims (payload):

```json
{
  "iss": "Gravitee.io AM",
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

You can extract the issuer from JWT using the following Expression Language statement:

<pre> {#context.attributes['jwt.claims']['iss']} </pre>





## Errors
These templates are defined at the API level, in the "Entrypoint" section for v4 APIs, or in "Response Templates" for v2 APIs.
The error keys sent by this policy are as follows:

| Key |
| ---  |
| JWT_MISSING_TOKEN |
| JWT_INVALID_TOKEN |
| JWT_INVALID_CERTIFICATE_BOUND_THUMBPRINT |
| JWT_REVOKED |



## Phases
The `jwt` policy can be applied to the following API types and flow phases.

### Compatible API types

* `PROXY`
* `MESSAGE`

### Supported flow phases:

* Request

## Compatibility matrix
Strikethrough text indicates that a version is deprecated.

| Plugin version| APIM |
| --- | ---  |
|6.x|4.6.x to latest |
|5.x|4.4.x to 4.5.x |
|4.x|4.0.x to 4.3.x |
|~~2.x~~|~~3.18.x to 3.20.x~~ |
|~~1.22.x~~|~~3.15.x to 3.17.x~~ |
|~~1.20.x to 1.21.x~~|~~3.10.x to 3.14.x~~ |
|~~Up to 1.19.x~~|~~Up to 3.9.x~~ |



## Configuration
### Gateway configuration
#### System proxy
If the option useSystemProxy is checked, proxy information will be read from JVM_OPTS, or from the gravitee.yml file if JVM_OPTS is not set.

#### Gateway keys
If the JWKS resolver is set to GATEWAY_KEYS then keys will be read from JVM_OPTS, or from the gravitee.yml file if JVM_OPTS is not set.

Examples: 


gravitee.yml
```YAML
system:
  proxy:
    type: HTTP      # HTTP, SOCK4, SOCK5
    host: localhost
    port: 3128
    username: user
    password: secret
```
gravitee.yml
```YAML
policy:
  jwt:
    issuer:
      my.authorization.server:
        default: ssh-rsa myValidationKey anEmail@domain.com
        kid-2016: ssh-rsa myCurrentValidationKey anEmail@domain.com
```



### Configuration options


#### 
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Client ID claim<br>`clientIdClaim`| string|  | | Claim where the client ID can be extracted. Configuring this field will override the standard behavior.|
| Confirmation Method Validation<br>`confirmationMethodValidation`| object|  | | <br/>See "Confirmation Method Validation" section.|
| JWKS URL connect timeout<br>`connectTimeout`| integer|  | `2000`| Only applies when the resolver is JWKS_URL|
| Extract JWT Claims<br>`extractClaims`| boolean|  | | Put claims into the 'jwt.claims' context attribute.|
| Follow HTTP redirects<br>`followRedirects`| boolean|  | | Only applies when the resolver is JWKS_URL|
| Propagate Authorization header<br>`propagateAuthHeader`| boolean|  | `true`| Allows to propagate Authorization header to the target endpoints|
| JWKS resolver<br>`publicKeyResolver`| enum (string)| ✅| `GIVEN_KEY`| Define how the JSON Web Key Set is retrieved<br>Values: `GIVEN_KEY` `GATEWAY_KEYS` `JWKS_URL`|
| JWKS URL request timeout<br>`requestTimeout`| integer|  | `2000`| Only applies when the resolver is JWKS_URL|
| Resolver parameter<br>`resolverParameter`| string|  | | Set the signature key GIVEN_KEY or a JWKS_URL following selected resolver (support EL).|
| Revocation Check<br>`revocationCheck`| object|  | | Define revocation check details. If enabled, will check the configured claim of the token against a cached revocation list and deny if a match is found. Disabled by default.<br/>See "Revocation Check" section.|
| Signature<br>`signature`| enum (string)| ✅| `RSA_RS256`| Define how the JSON Web Token must be signed.<br>Values: `RSA_RS256` `RSA_RS384` `RSA_RS512` `HMAC_HS256` `HMAC_HS384` `HMAC_HS512`|
| Token Type Validation<br>`tokenTypValidation`| object|  | | Define the token type to validate<br/>See "Token Type Validation" section.|
| Use system proxy<br>`useSystemProxy`| boolean|  | | Use system proxy (make sense only when resolver is set to JWKS_URL)|
| User claim<br>`userClaim`| string|  | `sub`| Claim where the user can be extracted|


#### Confirmation Method Validation (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Certificate Bound thumbprint (x5t#S256)<br>`certificateBoundThumbprint`| object|  | | <br/>See "Certificate Bound thumbprint (x5t#S256)" section.|
| Ignore missing CNF<br>`ignoreMissing`| boolean|  | | Will ignore CNF validation if the token doesn't contain any CNF information. Default is false.|


#### Certificate Bound thumbprint (x5t#S256) (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Enable certificate bound thumbprint validation<br>`enabled`| boolean|  | | Will validate the certificate thumbprint extracted from the access_token with the one provided by the client. The default is false.|
| Extract client certificate from headers<br>`extractCertificateFromHeader`| boolean|  | | Enabled to extract the client certificate from request header. Necessary when the M-TLS connection is handled by a proxy.|
| Header name<br>`headerName`| string|  | `ssl-client-cert`| Name of the header where to find the client certificate.|


#### Revocation Check (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| `additionalProperties`| string|  | | |
| Revocation list security configuration<br>`auth`| object|  | | <br/>See "Revocation list security configuration" section.|
| Revocation list connect timeout<br>`connectTimeout`| integer|  | `2000`| The connect timeout in milliseconds for retrieving the revocation list. Default is 2000.|
| Enable revocation check<br>`enabled`| boolean|  | | Will check if the token has been revoked. Default is false.|
| Revocation list follow redirects<br>`followRedirects`| boolean|  | | If should follow redirects for revocation list requests. Default is false.|
| Revocation list refresh interval<br>`refreshInterval`| integer|  | `300`| The refresh interval in seconds for the cached revocation list. Default is 300.|
| Revocation list request timeout<br>`requestTimeout`| integer|  | `2000`| The request timeout in milliseconds for retrieving the revocation list. Default is 2000.|
| Revocation claim<br>`revocationClaim`| string|  | `jti`| The string claim which will be checked against the revocation list. Default is 'jti'.|
| Revocation list URL<br>`revocationListUrl`| string|  | | The URL of the revocation list including protocol, should return a new line seperated list of strings, content type text/plain. No default is provided, required if enabled.|
| Revocation list use system proxy<br>`useSystemProxy`| boolean|  | | If should use system proxy for revocation list requests. Default is false.|


#### Revocation list security configuration (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Description  |
|:----------------------|:-----------------------|:----------:|:-------------|
| Type<br>`type`| object| ✅| Type of Revocation list security configuration<br>Values: `none` `basic` `token`|


#### Revocation list security configuration: No security `type = "none"` 
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| No properties | | | | | | | 

#### Revocation list security configuration: Basic security `type = "basic"` 
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Basic authentication configuration<br>`basic`| object| ✅| | <br/>See "Basic authentication configuration" section.|


#### Basic authentication configuration (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Description  |
|:----------------------|:-----------------------|:----------:|:-------------|
| Password<br>`password`| string<br>`[1, +Inf]`| ✅| Password which will be added to Authorization header in format 'basic user:password'|
| Username<br>`username`| string<br>`[1, +Inf]`| ✅| Username which will be added to Authorization header in format 'basic user:password'|


#### Revocation list security configuration: Token security `type = "token"` 
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Token authentication configuration<br>`token`| object| ✅| | <br/>See "Token authentication configuration" section.|


#### Token authentication configuration (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Description  |
|:----------------------|:-----------------------|:----------:|:-------------|
| Token value<br>`value`| string<br>`[1, +Inf]`| ✅| Token value which will be added to Authorization header in format 'bearer <token value>'|


#### Token Type Validation (Object)
| Name <br>`json name`  | Type <br>`constraint`  | Mandatory  | Default  | Description  |
|:----------------------|:-----------------------|:----------:|:---------|:-------------|
| Enable token type validation<br>`enabled`| boolean|  | | Will validate the token type extracted from the access_token with the one provided by the client. The default is false.|
| Expected values<br>`expectedValues`| array (string)|  | `[JWT]`| List of expected token types. If the token type is not in the list, the validation will fail.|
| Ignore case<br>`ignoreCase`| boolean|  | | Will ignore the case of the token type when comparing the expected values. Default is false.|
| Ignore missing token type<br>`ignoreMissing`| boolean|  | | Will ignore token type validation if the token doesn't contain any token type information. Default is false.|




## Examples



## Changelog

#### [6.1.5](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.4...6.1.5) (2025-07-17)


##### Bug Fixes

* Add support for trust_all ([6e292c1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/6e292c1732aff58b0243c5fc2be3abd637c1c8c9))

#### [6.1.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.3...6.1.4) (2025-07-01)


##### Bug Fixes

* bump gravitee-parent ([164afa8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/164afa8b95fa74efbe30f150465848b1346454d6))
* condition `.metrics()` use only if ctx is http ([acd3f04](https://github.com/gravitee-io/gravitee-policy-jwt/commit/acd3f0435de83e8204d722df41dae0fc7bf897ff))

#### [6.1.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.2...6.1.3) (2025-06-30)


##### Bug Fixes

* condition `.metrics()` use only if ctx is http ([cac9b37](https://github.com/gravitee-io/gravitee-policy-jwt/commit/cac9b37038bf0e19b1b7032d05c4af66385d322a))

#### [6.1.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.1...6.1.2) (2025-03-27)


##### Bug Fixes

* follow http redirect on v2 api ([ca861ce](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ca861ce0b95acc842933d7e103c2dcf2bc73447b))

#### [6.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.1.0...6.1.1) (2025-03-13)


##### Bug Fixes

* Properly resolve property value ([723382d](https://github.com/gravitee-io/gravitee-policy-jwt/commit/723382de91a580d5cf6be5d762ac9965579934f0))

### [6.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0...6.1.0) (2025-03-10)


##### Features

* add option to follow http redirects ([a5efe2e](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a5efe2e3d9645a3c039b32f59063c6ccfca6d19d))

### [6.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.2.0...6.0.0) (2024-12-30)


##### Bug Fixes

* **deps:** bump apim version ([7999be1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7999be10ad558c09feda4c2446ba72de081afaa5))
* invoke callback and complete on auth failure ([3f64243](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3f64243e2455609057d4b947c11c623c2cefdf07))
* use provided version of nimbus lib ([7063db4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7063db42c55cd6bd8a3021502f0bfaf03ce02f12))


##### Code Refactoring

* use new HttpSecurityPolicy and BaseExecutionContext interface ([8f6270f](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8f6270f8f22e06c972c141d12c28433b5da2f34e))


##### Features

* implement kafka security policy ([f1db2f1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/f1db2f1818a8cc60f8dfeace66a2c5a8d57bd600))
* set a max value for kafka token lifetime ([9195623](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9195623d3e7d3a0f2863ad0837f8cfcdb6295ea3))
* support custom token type header ([d08e658](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d08e65834b2eaf111dc9bdeeaa54223160a10fa4))


##### BREAKING CHANGES

* requires APIM 4.6+

### [6.0.0-alpha.5](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.4...6.0.0-alpha.5) (2024-12-30)


##### Bug Fixes

* **deps:** bump apim version ([7999be1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7999be10ad558c09feda4c2446ba72de081afaa5))


##### Features

* support custom token type header ([47e1918](https://github.com/gravitee-io/gravitee-policy-jwt/commit/47e19180b7cf95ca01172e0a844171c2a6ae141a))

### [6.0.0-alpha.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.3...6.0.0-alpha.4) (2024-11-29)


##### Features

* set a max value for kafka token lifetime ([9195623](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9195623d3e7d3a0f2863ad0837f8cfcdb6295ea3))

### [6.0.0-alpha.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.2...6.0.0-alpha.3) (2024-11-22)


##### Bug Fixes

* invoke callback and complete on auth failure ([3f64243](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3f64243e2455609057d4b947c11c623c2cefdf07))

### [6.0.0-alpha.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/6.0.0-alpha.1...6.0.0-alpha.2) (2024-11-13)


##### Features

* support custom token type header ([d08e658](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d08e65834b2eaf111dc9bdeeaa54223160a10fa4))

### [6.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.1.0...6.0.0-alpha.1) (2024-11-12)


##### Bug Fixes

* use provided version of nimbus lib ([7063db4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7063db42c55cd6bd8a3021502f0bfaf03ce02f12))


##### Code Refactoring

* use new HttpSecurityPolicy and BaseExecutionContext interface ([8f6270f](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8f6270f8f22e06c972c141d12c28433b5da2f34e))


##### Features

* implement kafka security policy ([f1db2f1](https://github.com/gravitee-io/gravitee-policy-jwt/commit/f1db2f1818a8cc60f8dfeace66a2c5a8d57bd600))


##### BREAKING CHANGES

* requires APIM 4.6+

### [5.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.1.0...5.2.0) (2024-11-07)

##### Features

* support custom token type header ([47e1918](https://github.com/gravitee-io/gravitee-policy-jwt/commit/47e19180b7cf95ca01172e0a844171c2a6ae141a))

### [5.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/5.0.0...5.1.0) (2024-10-25)


##### Features

* make jwks url timeouts configurable ([9e45980](https://github.com/gravitee-io/gravitee-policy-jwt/commit/9e459800127bf93940f5b5c8494bab13250375e6))

### [5.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.5...5.0.0) (2024-07-31)


##### chore

* **deps:** bump dependencies ([124d55a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/124d55abdf053b47f00a41addcd0c661232c061a))


##### BREAKING CHANGES

* **deps:** require APIM 4.4.x

#### [4.1.5](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.4...4.1.5) (2024-07-31)


##### Bug Fixes

* Revert do not use 4.1.4 with version lower or equal to 4.3.x => 4.1.x ([67d2208](https://github.com/gravitee-io/gravitee-policy-jwt/commit/67d22089b2601ddea8de0eaaac7c71b9dc9cd45c))

#### [4.1.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.3...4.1.4) (2024-07-30)


##### Bug Fixes

* **dependency:** VertxProxyOptionsUtils was moved to gravitee-node ([12f4e2a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/12f4e2a29670a5cc588c06dd92aae5b73a998d29))

#### [4.1.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.2...4.1.3) (2024-06-26)


##### Bug Fixes

* **gateway-keys:** when using gateway keys resolverParameter should be ignored ([ce04d1b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ce04d1b6af1dab317830311cbdf184ef5f7967ac))

#### [4.1.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.1...4.1.2) (2024-03-07)


##### Bug Fixes

* **deps:** update bcprov-jdk15on to bcprov-jdk18on and bcpkix-jdk15on to bcpkix-jdk18on ([337dee2](https://github.com/gravitee-io/gravitee-policy-jwt/commit/337dee2e04e6eb747dca93752c650598933865a1))

#### [4.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.1.0...4.1.1) (2023-09-12)


##### Bug Fixes

* bump gravitee common version ([5040027](https://github.com/gravitee-io/gravitee-policy-jwt/commit/504002776dc9d0e80e448d498c5a90033c6ca794))

### [4.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.1...4.1.0) (2023-09-05)


##### Features

* add new option allowing to check confirmation method ([3db2346](https://github.com/gravitee-io/gravitee-policy-jwt/commit/3db23464134d46d806308271f5090e19278e050c)), closes [x5t#S256](https://github.com/x5t/issues/S256)

#### [4.0.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0...4.0.1) (2023-07-20)


##### Bug Fixes

* update policy description ([214983d](https://github.com/gravitee-io/gravitee-policy-jwt/commit/214983d64b5a50bfcefeb2291f958951072a770d))

### [4.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.2.0...4.0.0) (2023-07-18)


##### Bug Fixes

* bump `gravitee-parent` to fix release on Maven Central ([e16c40a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/e16c40a22ca97828c7803dfbda6dd2d0e2819f3c))
* bump dependencies versions ([0d3e4dd](https://github.com/gravitee-io/gravitee-policy-jwt/commit/0d3e4dd782cb13bb4b6f4c6b0f56d5ad9444a6b5))
* properly handle token extraction ([702458b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/702458bb45c1fc083977e5b5f32bb036e5560062))
* simplify unauthorized message ([087383c](https://github.com/gravitee-io/gravitee-policy-jwt/commit/087383ce88e4c1fc810479b3506e7e7b849647f2))


##### chore

* **deps:** update gravitee-parent ([7f93871](https://github.com/gravitee-io/gravitee-policy-jwt/commit/7f93871cd891085da1763eb12dd5f92b7673497e))


##### BREAKING CHANGES

* **deps:** require Java17
* use apim version 4

### [4.0.0-alpha.4](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.3...4.0.0-alpha.4) (2023-07-07)


##### Bug Fixes

* bump `gravitee-parent` to fix release on Maven Central ([e16c40a](https://github.com/gravitee-io/gravitee-policy-jwt/commit/e16c40a22ca97828c7803dfbda6dd2d0e2819f3c))

### [4.0.0-alpha.3](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.2...4.0.0-alpha.3) (2023-07-06)


##### Bug Fixes

* properly handle token extraction ([702458b](https://github.com/gravitee-io/gravitee-policy-jwt/commit/702458bb45c1fc083977e5b5f32bb036e5560062))

### [4.0.0-alpha.2](https://github.com/gravitee-io/gravitee-policy-jwt/compare/4.0.0-alpha.1...4.0.0-alpha.2) (2023-07-05)


##### Bug Fixes

* simplify unauthorized message ([087383c](https://github.com/gravitee-io/gravitee-policy-jwt/commit/087383ce88e4c1fc810479b3506e7e7b849647f2))

### [4.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.2.0...4.0.0-alpha.1) (2023-07-04)


##### Bug Fixes

* bump dependencies versions ([0d3e4dd](https://github.com/gravitee-io/gravitee-policy-jwt/commit/0d3e4dd782cb13bb4b6f4c6b0f56d5ad9444a6b5))


##### BREAKING CHANGES

* use apim version 4

### [3.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.1.1...3.2.0) (2023-05-29)


##### Features

* provide execution phase in manifest ([92b15d9](https://github.com/gravitee-io/gravitee-policy-jwt/commit/92b15d97862e10dbbc43b421af34735fe2e86b8c))

#### [3.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.1.0...3.1.1) (2023-04-18)


##### Bug Fixes

* clean schema-form to make it compatible with gio-form-json-schema component ([dfd64f3](https://github.com/gravitee-io/gravitee-policy-jwt/commit/dfd64f358c5e71a47eb74414ba82885b9fcb33e3))

### [3.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.0...3.1.0) (2023-03-17)


##### Bug Fixes

* bump version of gateway api ([d062a55](https://github.com/gravitee-io/gravitee-policy-jwt/commit/d062a557795f4e3b279351599e1c591a51d25b1b))
* **deps:** upgrade gravitee-bom & alpha version ([b2da107](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b2da107c0998bd54be9294ff134e59f7cdd853db))


##### Features

* rename 'jupiter' package in 'reactive' ([2af6540](https://github.com/gravitee-io/gravitee-policy-jwt/commit/2af6540ff562c27ea64670051ef4f667eef12d42))

### [3.1.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.1-alpha.1...3.1.0-alpha.1) (2023-03-13)


##### Features

* rename 'jupiter' package in 'reactive' ([aaae6c5](https://github.com/gravitee-io/gravitee-policy-jwt/commit/aaae6c5802e4b1a652d630f398adcdd2c34f2b58))

#### [3.0.1-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/3.0.0...3.0.1-alpha.1) (2023-02-02)


##### Bug Fixes

* bump version of gateway api ([ae0bdad](https://github.com/gravitee-io/gravitee-policy-jwt/commit/ae0bdadaba7adc9c1469d7a2c2d48f64237ff170))

### [3.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.4.0...3.0.0) (2022-12-09)


##### chore

* bump to rxJava3 ([a69c5b4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a69c5b47b3a0e846d27e00382b8989856755cfdc))


##### BREAKING CHANGES

* rxJava3 required

### [3.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.4.0...3.0.0-alpha.1) (2022-10-19)


##### chore

* bump to rxJava3 ([a69c5b4](https://github.com/gravitee-io/gravitee-policy-jwt/commit/a69c5b47b3a0e846d27e00382b8989856755cfdc))


##### BREAKING CHANGES

* rxJava3 required

### [2.4.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.3.0...2.4.0) (2022-09-05)


##### Bug Fixes

* plan selection for v3 engine ([82d4a49](https://github.com/gravitee-io/gravitee-policy-jwt/commit/82d4a49c89ba418d24e7b6a90ad4f641a204dcab))


##### Features

* improve execution context structure ([1b5a166](https://github.com/gravitee-io/gravitee-policy-jwt/commit/1b5a166a252011ee1066ad61901c7c9d5938b586)), closes [gravitee-io/issues#8386](https://github.com/gravitee-io/issues/issues/8386)

### [2.3.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.2.0...2.3.0) (2022-08-16)


##### Features

* migrate to the new version of Jupiter's SecurityPolicy ([b384ee8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b384ee8047ac25361a3df9ba23683905e301d96b))

### [2.3.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.2.0...2.3.0) (2022-08-16)


##### Features

* migrate to the new version of Jupiter's SecurityPolicy ([b384ee8](https://github.com/gravitee-io/gravitee-policy-jwt/commit/b384ee8047ac25361a3df9ba23683905e301d96b))

### [2.2.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.1.1...2.2.0) (2022-08-08)


##### Features

* **sme:** update security policy to be compatible with async reactor ([50f6426](https://github.com/gravitee-io/gravitee-policy-jwt/commit/50f64262a1e81eee3b8774e7a5069583ec87a7ee))

#### [2.1.1](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.1.0...2.1.1) (2022-06-30)


##### Bug Fixes

* **jupiter:** support plain text hmac key ([8ec1fa9](https://github.com/gravitee-io/gravitee-policy-jwt/commit/8ec1fa91f9919ba502532995a6f12afc4b46a9e6)), closes [gravitee-io/issues#7947](https://github.com/gravitee-io/issues/issues/7947)

### [2.1.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/2.0.0...2.1.0) (2022-06-10)


##### Features

* **jupiter:** move to Jupiter SecurityPolicy ([24bbdac](https://github.com/gravitee-io/gravitee-policy-jwt/commit/24bbdacdc56d9063c3744d9858e2c2dff02c7397))

### [2.0.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/1.22.0...2.0.0) (2022-05-24)


##### Code Refactoring

* use common vertx proxy options factory ([92d2da5](https://github.com/gravitee-io/gravitee-policy-jwt/commit/92d2da534641726ace500abc91db718941208461))


##### BREAKING CHANGES

* this version requires APIM in version 3.18 and upper

### [1.22.0](https://github.com/gravitee-io/gravitee-policy-jwt/compare/1.21.0...1.22.0) (2022-01-21)


##### Features

* **headers:** Internal rework and introduce HTTP Headers API ([28ea9c6](https://github.com/gravitee-io/gravitee-policy-jwt/commit/28ea9c600f08cf76d1aa0df463c418a66cbc4753)), closes [gravitee-io/issues#6772](https://github.com/gravitee-io/issues/issues/6772)

