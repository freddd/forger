use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Name, X509},
};
use serde_json::{json, Value};

use crate::{e, n};

pub struct JWK {}

impl JWK {
    pub fn new() -> JWK {
        JWK {}
    }
    pub fn execute(&self, private_key: Rsa<Private>, x5c: bool) {
        let mut jwk = json!({
            "kty": "RSA",
            "kid": "xyz",
            "use": "sig",
            "n": n(private_key.clone()),
            "e": e(private_key.clone()),
        });

        if x5c {
            jwk["x5c"] = Value::from(base64::encode_config(
                self.create_cert(private_key)
                    .public_key()
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap(),
                base64::URL_SAFE_NO_PAD,
            ));
        }

        println!("{}", json!({ "keys": [jwk] }))
    }

    fn create_cert(&self, rsa: Rsa<Private>) -> X509 {
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
            .unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        builder.build()
    }
}
