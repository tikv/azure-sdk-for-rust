use azure_core::{
    base64,
    error::{ErrorKind, ResultExt},
};
use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, sign::Signer};

pub fn sign(data: &str, key: &str) -> azure_core::Result<String> {
    let dkey = base64::decode(key)?;
    let signature = || -> Result<Vec<u8>, ErrorStack> {
        let pkey = PKey::hmac(&dkey)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(data.as_bytes())?;
        Ok(signer.sign_to_vec()?)
    }()
    .with_context(ErrorKind::DataConversion, || {
        format!("failed to create hmac from key")
    })?;
    Ok(base64::encode(signature))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hmac_sign() {
        let data = "create hmac signature for data";
        let key = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

        let sig = super::sign(data, key).unwrap();

        let expected_sig = "D/y9XyIEdUzEbdV570h8dou/mfkbMA1lKCOPqPDPAd0=";
        assert_eq!(sig, expected_sig);
    }
}
