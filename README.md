# FORGER
![CI](https://github.com/freddd/forger/workflows/CI/badge.svg)

## print
Prints the base64 token as json (skipping the signature)

EXAMPLE USAGE:
```bash
forger <token> print
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

EXAMPLE USAGE:
```bash
forger <token> alter --increase-expiry=10 --subject=fe6ba0f0-9965-40d2-88bc-741bf4d7db04
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
