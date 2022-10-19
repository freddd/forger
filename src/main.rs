use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use clap::{App, Arg, SubCommand};
use env_logger::Env;
use hmac::{Hmac, Mac};
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
                    Arg::with_name("symmetric-secret-path")
                        .long("symmetric-secret-path")
                        .required(false)
                        .help("path to secret to use to create signature (HMAC)")
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
            print::Print::new().execute(arg_matches.value_of("token").unwrap())
        }
        ("jwk", Some(args_matches)) => {
            let private_key = match args_matches.value_of("key") {
                Some(key_path) => {
                    debug!("using key from path: {}", key_path);
                    Rsa::private_key_from_pem(read_private_key(key_path).as_bytes()).unwrap()
                }
                None => Rsa::generate(2048).unwrap(),
            };

            jwk::JWK::new().execute(private_key, args_matches.is_present("x5c"));
        }
        ("brute-force", Some(args_matches)) => {
            brute_force::BruteForce::new().execute(
                args_matches.value_of("token").unwrap(),
                args_matches.value_of("wordlist").unwrap(),
            );
        }
        ("alter", Some(arg_matches)) => {
            alter::Alter::new(
                arg_matches.value_of("algo"),
                arg_matches.value_of("increase-expiry"),
                arg_matches.value_of("subject"),
                arg_matches.value_of("jku"),
                arg_matches.value_of("x5u"),
                arg_matches.value_of("key"),
                arg_matches.is_present("embed-jwk"),
                arg_matches.values_of("prop"),
                arg_matches.value_of("symmetric-secret-path"),
            )
            .execute(arg_matches.value_of("token").unwrap());
        }
        _ => unreachable!(),
    }
}

fn e(key: Rsa<Private>) -> String {
    let p = Rsa::public_key_from_pem(&key.public_key_to_pem().unwrap()[..]).unwrap();
    base64::encode_config(p.e().to_vec(), base64::URL_SAFE_NO_PAD)
}

fn n(key: Rsa<Private>) -> String {
    let p = Rsa::public_key_from_pem(&key.public_key_to_pem().unwrap()[..]).unwrap();
    base64::encode_config(p.n().to_vec(), base64::URL_SAFE_NO_PAD)
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
