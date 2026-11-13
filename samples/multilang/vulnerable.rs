use std::process::Command;
use reqwest::Client;

fn run(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).status().unwrap();
}

fn find_user(id: &str) -> String {
    format!("SELECT * FROM users WHERE id = {}", id)
}

fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

const API_TOKEN: &str = "example-github-token";
