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
use rayon::prelude::*;
use serde_json::{Map, Value};
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
                    Arg::with_name("secret-path")
                        .long("secret-path")
                        .required(false)
                        .help("path to secret to use to create signature")
                        .takes_value(true),
                ),
        )
        .subcommand(SubCommand::with_name("print").about("prints decoded JWT"))
        .subcommand(
            SubCommand::with_name("brute-force") // a slower version than "hashcat jwt.txt -m 16500 -a 3 -w 2 ?d?d?d?d"
                .about("tries to brute force the secret used to sign (only HMAC)")
                .arg(
                    Arg::with_name("wordlist")
                        .long("wordlist")
                        .required(true)
                        .help("path to the wordlist to be used")
                        .takes_value(true),
                ),
        )
        .arg(Arg::with_name("token").required(true))
        .get_matches();

    let token_parts_b64: Vec<&str> = matches.value_of("token").unwrap().split('.').collect();
    let token = match base64_to_map(token_parts_b64.clone()) {
        Ok(p) => p,
        Err(err) => {
            panic!("failed to decode token: {:#?}", err)
        }
    };

    match matches.subcommand() {
        ("print", Some(_arg_matches)) => {
            let json_str: Vec<String> = token
                .into_iter()
                .map(|p| serde_json::to_string_pretty(&p).unwrap())
                .collect();
            println!("{}", json_str.join("."))
        }
        ("brute-force", Some(arg_matches)) => {
            let alg = token[0]["alg"].as_str().unwrap();
            if !alg.starts_with("HS") {
                println!("algorithm not supported");
                return;
            }

            let words = lines_from_file(arg_matches.value_of("wordlist").unwrap());
            let current_sig = token_parts_b64[2];
            let header_and_payload = vec![token_parts_b64[0], token_parts_b64[1]].join(".");

            words.par_iter().for_each(|word| {
                let new_sig = match alg {
                    "HS256" => {
                        println!("{}", word);
                        sign_payload::<HmacSha256>(header_and_payload.to_string(), word.as_bytes())
                    }
                    "HS384" => {
                        sign_payload::<HmacSha384>(header_and_payload.to_string(), word.as_bytes())
                    }
                    "HS512" => {
                        sign_payload::<HmacSha512>(header_and_payload.to_string(), word.as_bytes())
                    }
                    _ => unreachable!("algorithm not supported"),
                };

                if new_sig == current_sig {
                    println!("the secret is: {}", word)
                }
            });
        }
        ("alter", Some(arg_matches)) => {
            let mut header = token[0].clone();
            let mut claims = token[1].clone();

            if let Some(increase) = arg_matches.value_of("increase-expiry") {
                let original_expiry = claims["exp"].as_u64().unwrap_or(0);
                claims["exp"] = Value::from(original_expiry + increase.parse::<u64>().unwrap());
            }

            if let Some(s) = arg_matches.value_of("subject") {
                claims["sub"] = Value::from(s);
            }

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
                debug!("{}", secret.trim());

                let signature: String = match algo {
                    "None" => String::from(""),
                    "HS256" => {
                        debug!("computing new signature for: HS256");
                        sign_payload::<HmacSha256>(encoded.join("."), secret.trim().as_bytes())
                    }
                    "HS384" => {
                        debug!("computing new signature for: HS384");
                        sign_payload::<HmacSha384>(encoded.join("."), secret.trim().as_bytes())
                    }
                    "HS512" => {
                        debug!("computing new signature for: HS512");
                        sign_payload::<HmacSha512>(encoded.join("."), secret.trim().as_bytes())
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

fn sign_payload<T: Mac + NewMac>(token: String, secret: &[u8]) -> String {
    let mut mac = T::new_varkey(secret).unwrap();
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
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
            let json_str = String::from_utf8(base64::decode(part).unwrap());
            let parsed: Value = serde_json::from_str(&json_str.unwrap()).unwrap();
            parsed.as_object().unwrap().clone()
        })
        .collect();

    Ok(parts_decoded)
}
