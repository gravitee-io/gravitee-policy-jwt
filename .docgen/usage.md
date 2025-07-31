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

