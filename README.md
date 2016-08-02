Json Web Token validator Policy
===============================

## Context

Some authorization servers use oauth2 protocole to provide access tokens.
These access token can be on JWS/JWT format. (see below RFC)
[JWS (Json Web Signature) standard RFC](https://tools.ietf.org/html/rfc7515)
[JWT (Json Web Token) standard RFC](https://tools.ietf.org/html/rfc7519)

## JWT Example

A JWT is composed of three part : header, payload, signature.
You can see some sample [here](http://jwt.io)

The header will contain attributes indicating the algorithm used to sign the token.
The payload contains some informations inserted by the AS (Authorization Server). 
Both header & payload are encoded on Base64, so anyone can read it's content.
The third and last part is the signature. (Please see RFC for more details)

## Policy aim (on request)

The aim of this policy is to validate the token signature & expiration date before sending the api call to the target backend.
blablabla....
A short description of the motivation behind the creation and maintenance of the project. This should explain **why** the project exists.

## Configuration

To validate the token signature, the policy need to use the associated Authorization Servers public key.
The policy ask you to select among three (GIVEN_KEY, GIVEN_ISSUER, GATEWAY_ISSUER) way of retrieving the needed public key.

 - **GIVEN_KEY** : You will provide a key (ssh-rsa KEY xx@yy.zz) format.
 - **GIVEN_ISSUER** : If you want to filter on a few authorization servers, then you only need to specify the issuer name. Thanks to that, the gateway will only accept JWTs having an allowed issuer attribute. As for the GATEWAY_KEYS, the issuer is also used to retrieve the public key from the gravitee.yml gateway settings.
 - **GATEWAY_KEYS** : Some public key can be set into gravitee gateway settings

    On this mode, the policy will inspect the jwt :
     - header in order to extract the key id (kid attribute) of the public key. If none then we set it as ‘default’.
     - claims (payload) in order to extract the issuer (iss attribute)

    ***Thanks to both values, the gateway will be able to retrieve the corresponding public key.***

## Http status code

Return **401** in case of bad token format, content, signature, expired token or any others problem which forbid the policy to validate the token.


## Contributors

For any comments, please use this github issue [link](https://github.com/gravitee-io/issues/issues/46)

