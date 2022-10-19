use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use clap::{Arg, Command};
use env_logger::Env;
use hmac::{digest::KeyInit, Hmac, Mac};
use log::debug;
use openssl::{pkey::Private, rsa::Rsa};

use serde_json::{Map, Value};

use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

mod alter;
mod brute_force;
mod jwk;
mod print;

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let matches = clap::Command::new("forger")
        .version("1.0")
        .author("freddd")
        .about("Alter JWTs")
        .subcommand(
            Command::new("alter")
                .about("alters the JWT")
                .arg(
                    Arg::new("increase-expiry")
                        .short('i')
                        .long("increase-expiry")
                        .required(false)
                        .help("increases expiry with the given milliseconds")
                        .num_args(1),
                )
                .arg(
                    Arg::new("subject")
                        .short('s')
                        .long("subject")
                        .required(false)
                        .help("change subject")
                        .num_args(1),
                )
                .arg(
                    Arg::new("prop")
                        .short('p')
                        .long("prop")
                        .required(false)
                        .num_args(1..)
                        .help("key=value, gives the key the given value"),
                )
                .arg(
                    Arg::new("algo")
                        .short('a')
                        .long("algo")
                        .required(false)
                        .help("changes algo to the given algo")
                        .num_args(1),
                )
                .arg(
                    Arg::new("embed-jwk")
                        .short('e')
                        .long("embed-jwk")
                        .required(false)
                        .help("creates an RSA key and embeds it (CVE-2018-0114)")
                        .num_args(0),
                )
                .arg(
                    Arg::new("jku")
                        .long("jku")
                        .required(false)
                        .help("jku url (example: https://www.x.y/.well-known/jwks.json)")
                        .num_args(1),
                )
                .arg(
                    Arg::new("key")
                        .long("key")
                        .required(false)
                        .help("path to private key to sign with (.pem), required when using jku/x5c and optional for embed-jwk")
                        .num_args(1),
                )
                .arg(
                    Arg::new("x5u")
                        .long("x5u")
                        .required(false)
                        .help("x5u url (example: http://x.y/.well-known/jwks_with_x5c.json)")
                        .num_args(1),
                )
                .arg(
                    Arg::new("symmetric-secret-path")
                        .long("symmetric-secret-path")
                        .required(false)
                        .help("path to secret to use to create signature (HMAC)")
                        .num_args(1),
                )
                .arg(Arg::new("token").required(true)),
        )
        .subcommand(Command::new("print").about("prints decoded JWT").arg(Arg::new("token").required(true)))
        .subcommand(Command::new("jwk").about("creates a jwk json file (RSA256)").arg(
            Arg::new("key")
                .long("key")
                .required(false)
                .help("path to a private key to resolve the public key to convert to jwk")
                .num_args(1),
        ).arg(
            Arg::new("x5c")
                .long("x5c")
                .required(false)
                .help("adds a cert to jwk.json")
                .num_args(0),
        ))
        .subcommand(
            Command::new("brute-force")
                .about("tries to brute force the secret used to sign (only HMAC)")
                .arg(
                    Arg::new("wordlist")
                        .long("wordlist")
                        .required(true)
                        .help("path to the wordlist to be used")
                        .num_args(1),
                )
                .arg(Arg::new("token").required(true)),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("print", matches)) => {
            print::Print::new().execute(matches.get_one::<String>("token").unwrap())
        }
        Some(("jwk", matches)) => {
            let private_key = match matches.get_one::<String>("key") {
                Some(key_path) => {
                    debug!("using key from path: {}", key_path);
                    Rsa::private_key_from_pem(read_private_key(key_path).as_bytes()).unwrap()
                }
                None => Rsa::generate(2048).unwrap(),
            };

            jwk::Jwk::new().execute(private_key, matches.contains_id("x5c"));
        }
        Some(("brute-force", matches)) => {
            brute_force::BruteForce::new().execute(
                matches.get_one::<String>("token").unwrap(),
                matches.get_one::<String>("wordlist").unwrap(),
            );
        }
        Some(("alter", matches)) => {
            let props = matches
                .get_many::<String>("prop")
                .map(|vals| vals.collect::<Vec<_>>())
                .unwrap_or_default();

            alter::Alter::new(
                matches.get_one::<String>("algo"),
                matches.get_one::<String>("increase-expiry"),
                matches.get_one::<String>("subject"),
                matches.get_one::<String>("jku"),
                matches.get_one::<String>("x5u"),
                matches.get_one::<String>("key"),
                matches.contains_id("embed-jwk"),
                props,
                matches.get_one::<String>("symmetric-secret-path"),
            )
            .execute(matches.get_one::<String>("token").unwrap().to_string());
        }
        _ => unreachable!(),
    };
}

fn e(key: Rsa<Private>) -> String {
    let p = Rsa::public_key_from_pem(&key.public_key_to_pem().unwrap()[..]).unwrap();
    base64::encode_config(p.e().to_vec(), base64::URL_SAFE_NO_PAD)
}

fn n(key: Rsa<Private>) -> String {
    let p = Rsa::public_key_from_pem(&key.public_key_to_pem().unwrap()[..]).unwrap();
    base64::encode_config(p.n().to_vec(), base64::URL_SAFE_NO_PAD)
}

fn sign_payload_using_hmac<T: Mac + KeyInit>(token: String, secret: &[u8]) -> String {
    let mut mac = <T as Mac>::new_from_slice(secret).unwrap();
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
}

fn read_private_key(filename: impl AsRef<Path>) -> String {
    std::fs::read_to_string(filename).expect("Something went wrong reading the file")
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
