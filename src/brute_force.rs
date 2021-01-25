use crate::{
    base64_to_map, lines_from_file, sign_payload_using_hmac, HmacSha256, HmacSha384, HmacSha512,
};
use rayon::prelude::*;
pub struct BruteForce {}

impl BruteForce {
    pub fn new() -> BruteForce {
        BruteForce {}
    }
    pub fn execute(&self, t: &str, wordlist: &str) {
        let token_parts_b64: Vec<&str> = t.split('.').collect();
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

        let words = lines_from_file(wordlist);
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
}
