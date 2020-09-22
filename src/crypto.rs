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

type Aes256Cbc = block_modes::Cbc<Aes256, Iso7816>;
type HmacSha256 = Hmac<Sha256>;

pub const HEADER_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Crypto {
    key: [u8; 32],
    salt: Vec<u8>,
    init_vec: Vec<u8>,
}

impl Crypto {
    pub async fn new_encrypter(password: &SecVec<u8>) -> anyhow::Result<Self> {
        // generate random values
        let rng = thread_rng();
        let salt: Vec<u8> = Standard.sample_iter(rng).take(16).collect();
        let init_vec: Vec<u8> = Standard.sample_iter(rng).take(16).collect();

        // derive key
        let derived_key = Hkdf::<Sha256>::new(Some(&salt[..]), &password[..]);
        let mut key = [0u8; 32];
        derived_key.expand(&[], &mut key).unwrap();

        Ok(Crypto {
            key,
            salt,
            init_vec,
        })
    }

    pub async fn new_decrypter(
        password: &SecVec<u8>,
        salt: Vec<u8>,
        init_vec: Vec<u8>,
    ) -> anyhow::Result<Self, DecryptionError> {
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

    pub fn header(&self) -> Vec<u8> {
        let mut header = self.salt.clone();
        header.append(&mut self.init_vec.clone());
        header
    }
}

// let salt = header[..16].to_vec();
// let init_vec = header[16..32].to_vec();
pub fn split_header(header: &[u8]) -> Result<(&[u8], &[u8]), DecryptionError> {
    if header.len() != HEADER_LEN {
        return Err(DecryptionError::InvalidCipherLength);
    }
    Ok((&header[..16], &header[16..]))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn successful_encrypt_decrypt() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let mut cipher_package = Cursor::new(Vec::new());

        // encrypt
        let c = Crypto::new_encrypter(&password)
            .await
            .expect("error creating encrypter");
        cipher_package.write_all(&c.header()).await.unwrap();

        let ciphertext = c.encrypt(message.clone()).await;
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        cipher_package
            .write_u32(ciphertext.len() as u32)
            .await
            .unwrap();
        cipher_package.write_all(&ciphertext).await.unwrap();
        cipher_package.set_position(0);

        // decrypt
        let mut header = [0u8; HEADER_LEN];
        cipher_package.read(&mut header).await.unwrap();
        let (salt, init_vec) = split_header(&header).unwrap();
        let d = Crypto::new_decrypter(&password, salt.to_vec(), init_vec.to_vec())
            .await
            .expect("error creating crypto from cipher package");

        let chunk_size = cipher_package.read_u32().await.unwrap();
        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size as usize);
        cipher_package.read_buf(&mut buf).await.unwrap();
        let decrypted_text = d.decrypt(&buf).await.unwrap();
        assert_eq!(&message.unsecure(), &decrypted_text.unsecure());
    }

    #[tokio::test]
    async fn incomplete_package() {
        let header = b"012345";
        let decryption_err = split_header(&header[..]).unwrap_err();
        assert_eq!(
            decryption_err.to_string(),
            "cipher text does not contain all necessary elements"
        );
    }

    #[tokio::test]
    async fn invalid_checksum() {
        let password = SecVec::from("0123456789ABCDEF0123456789ABCDEF");
        let message = SecVec::from("this is a very secret message!!!");
        let mut cipher_package = Cursor::new(Vec::new());
        let c = Crypto::new_encrypter(&password)
            .await
            .expect("could not create encryptor");
        cipher_package.write_all(&c.header()).await.unwrap();
        let ciphertext = c.encrypt(message.clone()).await;
        assert_ne!(&message.unsecure()[..], &ciphertext[..]);
        cipher_package.write_all(&ciphertext).await.unwrap();
        let end = ciphertext.len() - 4;
        let decryption_err = c.decrypt(&ciphertext[..end]).await.unwrap_err();
        assert_eq!(decryption_err.to_string(), "HMAC verification failed");
    }
}
