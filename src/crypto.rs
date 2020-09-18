use aes::Aes256;
use block_modes::block_padding::Iso7816;
use block_modes::{BlockMode, InvalidKeyIvLength};
use crypto_mac::MacError;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use rand::distributions::{Distribution, Standard};
use rand::thread_rng;
use secstr::SecVec;
use sha2::Sha256;
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type Aes256Cbc = block_modes::Cbc<Aes256, Iso7816>;
type HmacSha256 = Hmac<Sha256>;

const HEADER_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Crypto {
    key: [u8; 32],
    salt: Vec<u8>,
    init_vec: Vec<u8>,
}

impl Crypto {
    pub async fn new_encrypter(
        password: &SecVec<u8>,
        output: &mut (dyn AsyncWrite + Unpin + Send + Sync),
    ) -> anyhow::Result<Self> {
        // generate random values
        let rng = thread_rng();
        let salt: Vec<u8> = Standard.sample_iter(rng).take(16).collect();
        let init_vec: Vec<u8> = Standard.sample_iter(rng).take(16).collect();

        // derive key
        let derived_key = Hkdf::<Sha256>::new(Some(&salt[..]), &password[..]);
        let mut key = [0u8; 32];
        derived_key.expand(&[], &mut key).unwrap();

        // write header
        output.write_all(&salt).await?;
        output.write_all(&init_vec).await?;

        Ok(Crypto {
            key,
            salt,
            init_vec,
        })
    }

    // let salt = header[..16].to_vec();
    // let init_vec = header[16..32].to_vec();
    pub async fn new_decrypter(
        password: &SecVec<u8>,
        cipher_package: &mut (dyn AsyncRead + Unpin + Send + Sync),
    ) -> anyhow::Result<Self, DecryptionError> {
        let mut header = [0; HEADER_LEN];
        let bytes_read = cipher_package.read(&mut header).await?;
        if bytes_read < HEADER_LEN {
            return Err(DecryptionError::InvalidCipherLength);
        }
        let salt = Vec::from(&header[..16]);
        let init_vec = Vec::from(&header[16..32]);

        // derrive key
        let h = Hkdf::<Sha256>::new(Some(&salt), &password.unsecure()[..]);
        let mut key = [0u8; 32];
        h.expand(&[], &mut key).unwrap();

        Ok(Crypto {
            key,
            salt,
            init_vec,
        })
    }

    pub async fn encrypt(&self, plaintext: SecVec<u8>) -> Vec<u8> {
        // encrypt
        let cipher = Aes256Cbc::new_var(&self.key[..], &self.init_vec).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext.unsecure());

        // calculate hmac
        let mut mac = HmacSha256::new_varkey(&self.key[..]).unwrap();
        mac.update(&ciphertext[..]);
        let checksum = mac.finalize().into_bytes();

        // build package
        let mut result: Vec<u8> = Vec::new();
        result.extend(self.salt.clone());
        result.extend(self.init_vec.clone());
        result.extend(checksum);
        result.extend(ciphertext);
        result
    }

    // let checksum = cipher_package[..32].to_vec();
    // let ciphertext = cipher_package[32..].to_vec();
    pub async fn decrypt(&self, cipher_package: &[u8]) -> Result<SecVec<u8>, DecryptionError> {
        // verify hmac
        let mut mac = HmacSha256::new_varkey(&self.key[..]).unwrap();
        mac.update(&cipher_package[32..]);
        mac.verify(&cipher_package[..32])?;

        // decrypt
        let cipher = Aes256Cbc::new_var(&self.key[..], &self.init_vec)?;
        let plaintext = cipher.decrypt_vec(&cipher_package[32..]).unwrap();

        Ok(SecVec::new(plaintext))
    }
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("cipher text does not contain all necessary elements")]
    InvalidCipherLength,
    #[error("HMAC verification failed")]
    HmacVerificationFailure(#[from] MacError),
    #[error("Improper key length")]
    KeyError(#[from] InvalidKeyIvLength),
    #[error("Improper header length")]
    HeaderError(#[from] io::Error),
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn successful_encrypt_decrypt() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let cipher_package = Cursor::new(Vec::new());
        let c = Crypto::new_encrypter(&password, &mut cipher_package)
            .await
            .expect("error creating encrypter");
        let ciphertext = c.encrypt(message.clone()).await;
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        cipher_package.write_all(&ciphertext);
        cipher_package.set_position(0);
        let d = Crypto::new_decrypter(&password, &mut cipher_package)
            .await
            .expect("error creating crypto from cipher package");
        let decrypted_text = d.decrypt(&ciphertext).await.unwrap();
        assert_eq!(&message.unsecure(), &decrypted_text.unsecure());
    }

    #[tokio::test]
    async fn incomplete_package() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let cipher_package = Cursor::new(Vec::from("0123456789ABCDEF"));
        let decryption_err = Crypto::new_decrypter(&password, &mut cipher_package)
            .await
            .unwrap_err();
        assert_eq!(
            decryption_err.to_string(),
            "cipher text does not contain all necessary elements"
        );
    }

    #[tokio::test]
    async fn invalid_checksum() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let cipher_package = Cursor::new(Vec::new());
        let c = Crypto::new_encrypter(&password, &mut cipher_package)
            .await
            .expect("could not create encryptor");
        let ciphertext = c.encrypt(message.clone()).await;
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        cipher_package.write_all(&ciphertext);
        let end = ciphertext.len() - 4;
        let decryption_err = c.decrypt(&ciphertext[..end]).await.unwrap_err();
        assert_eq!(decryption_err.to_string(), "HMAC verification failed");
    }
}
