use std::error::Error;

use clap::{App, Arg, SubCommand};
use serde_json::{Map, Value};

fn main() {
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
                ),
        )
        .subcommand(SubCommand::with_name("print").about("prints decoded JWT"))
        .arg(Arg::with_name("token").required(true))
        .get_matches();

    let token_parts_b64: Vec<&str> = matches.value_of("token").unwrap().split(".").collect();
    let mut token = match base64_to_map(token_parts_b64.clone()) {
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
        ("alter", Some(arg_matches)) => {
            let increase_expiry = arg_matches.value_of("increase-expiry");
            let claims = &mut token[1];

            if increase_expiry.is_some() {
                let original_expiry = claims["exp"].as_u64().unwrap_or(0);
                claims["exp"] =
                    Value::from(original_expiry + increase_expiry.unwrap().parse::<u64>().unwrap());
            }

            let subject = arg_matches.value_of("subject");
            if subject.is_some() {
                claims["sub"] = Value::from(subject.unwrap());
            }

            // TODO: only does substitutions on top-level
            match arg_matches.values_of("prop") {
                Some(values) => {
                    for val in values {
                        let key_vals: Vec<&str> = val.split("=").collect();
                        if claims.contains_key(key_vals[0]) {
                            claims[key_vals[0]] = Value::from(key_vals[1]);
                        }
                    }
                }
                None => {}
            }

            let encoded = token
                .into_iter()
                .map(|p| {
                    let json_str = serde_json::to_string(&p).unwrap();
                    base64::encode(&json_str)
                })
                .collect::<Vec<String>>();

            println!("{}", encoded.join(".") + "." + token_parts_b64[2])
        }
        _ => unreachable!(),
    }
}

fn base64_to_map(parts: Vec<&str>) -> Result<Vec<Map<String, Value>>, Box<dyn Error>> {
    let parts_decoded = parts
        .into_iter()
        .take(2) // skip signature as it's not base64
        .map(|part| {
            let json_str = String::from_utf8(base64::decode(part).unwrap());
            let parsed: Value = serde_json::from_str(&json_str.unwrap()).unwrap();
            parsed.as_object().unwrap().clone()
        })
        .collect();

    return Ok(parts_decoded);
}
