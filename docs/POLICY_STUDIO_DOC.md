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


