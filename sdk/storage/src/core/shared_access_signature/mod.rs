use chrono::{DateTime, Utc};
use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, sign::Signer};
use std::fmt;
use url::form_urlencoded;

pub mod account_sas;
pub mod service_sas;

pub trait SasToken {
    fn token(&self) -> String;
}

// TiKV won't run here, so it's OK to unwrap the error.
pub(crate) fn sign(key: &str, data: &str) -> String {
    let dkey = base64::decode(key).unwrap();
    let sig = || -> Result<Vec<u8>, ErrorStack> {
        let pkey = PKey::hmac(&dkey)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(data.as_bytes())?;
        Ok(signer.sign_to_vec()?)
    }()
    .unwrap();

    base64::encode(sig)
}

pub(crate) fn format_date(d: DateTime<Utc>) -> String {
    d.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub(crate) fn format_form(d: String) -> String {
    form_urlencoded::byte_serialize(d.as_bytes()).collect::<String>()
}

/// Specifies the protocol permitted for a request made with the SAS ([Azure documentation](https://docs.microsoft.com/rest/api/storageservices/create-service-sas#specifying-the-http-protocol)).
#[derive(Copy, Clone)]
pub enum SasProtocol {
    Https,
    HttpHttps,
}

impl fmt::Display for SasProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasProtocol::Https => write!(f, "https"),
            SasProtocol::HttpHttps => write!(f, "http,https"),
        }
    }
}
