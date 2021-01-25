use crate::base64_to_map;

pub struct Print {}

impl Print {
    pub fn new() -> Print {
        Print {}
    }
    pub fn execute(&self, t: &str) {
        let token_parts_b64: Vec<&str> = t.split('.').collect();
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
}
