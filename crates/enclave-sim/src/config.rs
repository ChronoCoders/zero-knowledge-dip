#[derive(Clone)]
pub struct Config {
    pub jwt_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "dev_secret_key_change_in_production".to_string());

        Ok(Self { jwt_secret })
    }
}
