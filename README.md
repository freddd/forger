# FORGER
![CI](https://github.com/freddd/forger/workflows/CI/badge.svg)

This cli aims to make it easier to work with JWTs when doing security reviews. Examples of use cases:

* Prints a decoded token
* Prints a jwk json file given a key (possibility to include a cert as well)
* Makes it possible to (in an easy way) changes values of properties in a JWT
* Generate self signed tokens
* etc

## print 
Prints the base64 token as json (skipping the signature)

```bash
USAGE:
    forger print <token>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <token>
```

Given the token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` the output will be:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}.{
  "iat": 1516239022,
  "name": "John Doe",
  "sub": "1234567890"
}
```

## alter
Alters the token given the input and returns a new `base64` encoded token. Only supports changing top-level claims.

```bash
USAGE:
    forger alter [FLAGS] [OPTIONS] <token>

FLAGS:
    -e, --embed-jwk    creates an RSA key and embeds it (CVE-2018-0114)
    -h, --help         Prints help information
    -V, --version      Prints version information

OPTIONS:
    -a, --algo <algo>                          changes algo to the given algo
    -i, --increase-expiry <increase-expiry>    increases expiry with the given milliseconds
    -j, --jku <jku>                            jku url (example: https://www.x.y/.well-known/jwks.json)
    -k, --key <key>                            path to private key to sign with (.pem), required when using jku/x5c and
                                               optional for embed-jwk
    -p, --prop <prop>...                       key=value, gives the key the given value
        --secret-path <secret-path>            path to secret to use to create signature
    -s, --subject <subject>                    change subject
    -x, --x5u <x5u>                            x5u url (example: http://x.y/.well-known/jwks_with_x5c.json)

ARGS:
    <token>
```

Given the token
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
and `--subject=fe6ba0f0-9965-40d2-88bc-741bf4d7db04` the output will be 
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6ImZlNmJhMGYwLTk5NjUtNDBkMi04OGJjLTc0MWJmNGQ3ZGIwNCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```
the header and signature is the same but the `sub` claims has changed.

## Brute force
```bash
USAGE:
    forger brute-force <token> --wordlist <wordlist>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --wordlist <wordlist>    path to the wordlist to be used

ARGS:
    <token>
```

## jwk
```bash
USAGE:
    forger jwk [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -x, --x5c        adds a cert to jwk.json

OPTIONS:
    -k, --key <key>    path to a private key to resolve the public key to convert to jwk
```

## Generate keys/cert

Generate private key:
```bash
openssl genrsa -out key.pem 2048
```

Generate cert using key:
```bash
openssl req -new -x509 -sha256 -key private.pem -out cert.pem -days 1095
```

Extract public key from cert:
```bash
openssl x509 -in certificate.pem -pubkey -noout
```
