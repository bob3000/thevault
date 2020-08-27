/*!

This library is made to encrypt data and is build upon the libraries from the
rust crypto project.

*/
use aes::Aes256;
use base64::DecodeError;
use block_modes::block_padding::Iso7816;
use block_modes::{BlockMode, InvalidKeyIvLength};
use crypto_mac::MacError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::distributions::{Distribution, Standard};
use rand::thread_rng;
use secstr::{SecStr, SecVec};
use sha2::Sha256;
use thiserror::Error;

type Aes256Cbc = block_modes::Cbc<Aes256, Iso7816>;
type HmacSha256 = Hmac<Sha256>;

pub fn encrypt(password: SecStr, plaintext: SecVec<u8>) -> Vec<u8> {
    // generate random values
    let rng = thread_rng();
    let salt: Vec<u8> = Standard.sample_iter(rng).take(16).collect();
    let init_vec: Vec<u8> = Standard.sample_iter(rng).take(16).collect();

    // derive key
    let derived_key = Hkdf::<Sha256>::new(Some(&salt[..]), &password[..]);
    let mut key = [0u8; 32];
    derived_key.expand(&[], &mut key).unwrap();

    // encrypt
    let cipher = Aes256Cbc::new_var(&key[..], &init_vec).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext.unsecure());

    // calculate hmac
    let mut mac = HmacSha256::new_varkey(&key[..]).unwrap();
    mac.update(&ciphertext[..]);
    let checksum = mac.finalize().into_bytes();

    // build package
    let mut result: Vec<u8> = Vec::new();
    result.extend(salt);
    result.extend(init_vec);
    result.extend(checksum);
    result.extend(ciphertext);

    // base64 encode
    base64::encode(result).as_bytes().to_vec()
}

/// let salt = cipher_package[..16].to_vec();
/// let init_vec = cipher_package[16..32].to_vec();
/// let checksum = cipher_package[32..64].to_vec();
/// let ciphertext = cipher_package[64..].to_vec();
pub fn decrypt(password: SecStr, cipher_package: &[u8]) -> Result<SecVec<u8>, DecryptionError> {
    if cipher_package.len() < 64 {
        return Err(DecryptionError::InvalidCipherLength);
    }
    // base64 decode
    let cpackage = base64::decode(cipher_package)?;

    // derrive key
    let h = Hkdf::<Sha256>::new(Some(&cpackage[..16]), &password.unsecure()[..]);
    let mut key = [0u8; 32];
    h.expand(&[], &mut key).unwrap();

    // verify hmac
    let mut mac = HmacSha256::new_varkey(&key[..]).unwrap();
    mac.update(&cpackage[64..]);
    mac.verify(&cpackage[32..64])?;

    // decrypt
    let cipher = Aes256Cbc::new_var(&key[..], &cpackage[16..32])?;
    let plaintext = cipher.decrypt_vec(&cpackage[64..]).unwrap();

    Ok(SecVec::new(plaintext))
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("cipher text does not contain all necessary elements")]
    InvalidCipherLength,
    #[error("HMAC verification failed")]
    HmacVerificationFailure(#[from] MacError),
    #[error("Improper key length")]
    KeyError(#[from] InvalidKeyIvLength),
    #[error("base64 decoding error")]
    Base64Error(#[from] DecodeError),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn successful_encrypt_decrypt() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let ciphertext = encrypt(password.clone(), message.clone());
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        let decrypted_text = decrypt(password, &ciphertext[..]).unwrap();
        assert_eq!(&message.unsecure(), &decrypted_text.unsecure());
    }

    #[test]
    fn base64_error() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let ciphertext = b"?".repeat(65);
        let decryption_err = decrypt(password, &ciphertext[..]).unwrap_err();
        assert_eq!(decryption_err.to_string(), "base64 decoding error");
    }

    #[test]
    fn incomplete_package() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let ciphertext = b"0123456789ABCDEF";
        let decryption_err = decrypt(password, &ciphertext[..]).unwrap_err();
        assert_eq!(
            decryption_err.to_string(),
            "cipher text does not contain all necessary elements"
        );
    }

    #[test]
    fn invalid_checksum() {
        let password = SecStr::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let ciphertext = encrypt(password.clone(), message.clone());
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        let end = ciphertext.len() - 4;
        let decryption_err = decrypt(password, &ciphertext[..end]).unwrap_err();
        assert_eq!(decryption_err.to_string(), "HMAC verification failed");
    }
}
