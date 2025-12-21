use rand::Rng;
use std::{thread, time};
use serde::{Serialize, Deserialize};
use regex::Regex;

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: u8,
    phones: Vec<String>,
}

fn main() {
    loop {
        // 1. Rand
        let mut rng = rand::thread_rng();
        let n: u8 = rng.gen();
        println!("Hello World from Rust! Random number: {}", n);

        // 2. Serde & Serde JSON
        let p = Person {
            name: "John Doe".to_string(),
            age: 30,
            phones: vec!["+44 1234567".to_string(), "+44 2345678".to_string()],
        };
        let j = serde_json::to_string(&p).unwrap();
        println!("Serialized Person: {}", j);

        // 3. Regex
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
        println!("Date match: {}", re.is_match("2014-01-01"));

        thread::sleep(time::Duration::from_secs(5));
    }
}
