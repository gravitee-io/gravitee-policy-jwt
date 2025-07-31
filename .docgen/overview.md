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
