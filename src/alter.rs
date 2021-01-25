use clap::Values;
use log::debug;
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use serde_json::{json, Value};

use crate::{
    base64_to_map, e, n, read_private_key, sign_payload_using_hmac, HmacSha256, HmacSha384,
    HmacSha512,
};

// TODO: Refactor to use proper types instead of just passing on Option<&str>
pub struct Alter {
    algo: Option<String>,
    increase_expiry: Option<String>,
    subject: Option<String>,
    jku: Option<String>,
    x5u: Option<String>,
    key: Option<String>,
    embed_jwk: bool,
    props: Vec<String>,
    secret_path: Option<String>,
}

impl Alter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algo: Option<&str>,
        increase_expiry: Option<&str>,
        subject: Option<&str>,
        jku: Option<&str>,
        x5u: Option<&str>,
        key: Option<&str>,
        embed_jwk: bool,
        props: Option<Values>,
        secret_path: Option<&str>,
    ) -> Alter {
        let properties = match props {
            Some(values) => values.map(str::to_string).collect(),
            None => {
                vec![]
            }
        };

        Alter {
            algo: algo.map(str::to_string),
            increase_expiry: increase_expiry.map(str::to_string),
            subject: subject.map(str::to_string),
            jku: jku.map(str::to_string),
            x5u: x5u.map(str::to_string),
            key: key.map(str::to_string),
            embed_jwk,
            props: properties,
            secret_path: secret_path.map(str::to_string),
        }
    }

    pub fn execute(&self, t: &str) {
        let token_parts_b64: Vec<&str> = t.split('.').collect();
        let token = match base64_to_map(token_parts_b64.clone()) {
            Ok(p) => p,
            Err(err) => {
                panic!("failed to decode token: {:#?}", err)
            }
        };

        let mut header = token[0].clone();
        let mut claims = token[1].clone();

        if let Some(increase) = self.increase_expiry.clone() {
            let original_expiry = claims["exp"].as_u64().unwrap_or(0);
            claims["exp"] = Value::from(original_expiry + increase.parse::<u64>().unwrap());
        }
        if let Some(s) = self.subject.clone() {
            claims["sub"] = Value::from(s);
        }

        if let Some(jku) = self.jku.clone() {
            header["jku"] = Value::from(jku);
        }

        if let Some(x5u) = self.x5u.clone() {
            header["x5u"] = Value::from(x5u);
        }

        let private_key = match self.key.clone() {
            Some(key_path) => {
                debug!("using key from path: {}", key_path);
                Rsa::private_key_from_pem(read_private_key(key_path).as_bytes()).unwrap()
            }
            None => Rsa::generate(2048).unwrap(),
        };

        // TODO: only does substitutions on top-level
        for val in self.props.clone() {
            let key_vals: Vec<&str> = val.split('=').collect();
            if claims.contains_key(key_vals[0]) {
                claims[key_vals[0]] = Value::from(key_vals[1]);
            }

            if header.contains_key(key_vals[0]) {
                header[key_vals[0]] = Value::from(key_vals[1]);
            }
        }

        if let Some(algo) = self.algo.clone() {
            header["alg"] = Value::from(algo);
        }

        // embed-jwk will remove the `kid` header, set alg to RS256 and add a new header called `jwk` with an embedded key
        if self.embed_jwk {
            header.remove("kid");
            header["alg"] = Value::from("RS256");

            header.insert(
                String::from("jwk"),
                json!({
                    "kty": "RSA",
                    "kid": "xyz",
                    "use": "sig",
                    "n": n(private_key.clone()),
                    "e": e(private_key.clone()),
                }),
            );
        }

        debug!("headers: {:#?}", header);
        debug!("claims: {:#?}", claims);

        let encoded = vec![header, claims]
            .into_iter()
            .map(|p| {
                let json_str = serde_json::to_string(&p).unwrap();
                base64::encode_config(&json_str, base64::URL_SAFE_NO_PAD)
            })
            .collect::<Vec<String>>();

        debug!("encoded: {:#?}", encoded);

        if let Some(algo) = self.algo.clone() {
            let secret = match self.secret_path.clone() {
                Some(path) => std::fs::read_to_string(path).unwrap(),
                None => String::from(""),
            };

            let signature: String = match algo.as_str() {
                "None" => String::from(""),
                "HS256" => {
                    debug!("computing new signature for: HS256");
                    sign_payload_using_hmac::<HmacSha256>(
                        encoded.join("."),
                        secret.trim().as_bytes(),
                    )
                }
                "HS384" => {
                    debug!("computing new signature for: HS384");
                    sign_payload_using_hmac::<HmacSha384>(
                        encoded.join("."),
                        secret.trim().as_bytes(),
                    )
                }
                "HS512" => {
                    debug!("computing new signature for: HS512");
                    sign_payload_using_hmac::<HmacSha512>(
                        encoded.join("."),
                        secret.trim().as_bytes(),
                    )
                }
                "RS256" => {
                    let keypair = PKey::from_rsa(private_key).unwrap();
                    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
                    signer.update(encoded.join(".").as_bytes()).unwrap();
                    base64::encode_config(signer.sign_to_vec().unwrap(), base64::URL_SAFE_NO_PAD)
                }
                _ => String::from(token_parts_b64[2]),
            };

            debug!("changed signature: {}", signature);
            println!("{}", encoded.join(".") + "." + &signature)
        } else {
            println!("{}", encoded.join(".") + "." + token_parts_b64[2])
        }
    }
}
